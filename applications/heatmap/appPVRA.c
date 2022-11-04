#include "enclavestate.h"
#include "appPVRA.h"


float LAT_HEATMAP_MAX = 40.25;
float LAT_HEATMAP_MIN = 39.5;
float LONG_HEATMAP_MAX = 116.75;
float LONG_HEATMAP_MIN = 116.0;
int HEATMAP_COUNT_THRESHOLD = 2;

/* COMMAND0 Kernel Definition */
struct cResponse addPersonalData(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    struct cResponse ret;
    ret.error = 0;
    memset(ret.heatmap_data, 0, sizeof(ret.heatmap_data));
    memset(ret.message, 0, 100);
    //printf("[apPVRA] Readable eCMD: [CI]:%d,%d} ", uidx, CI->test_result);

    if (enclave_state->appdata.num_data > MAX_DATA) {
        ret.error = 1;
        sprintf(ret.message, "data buffer already full");
        printf("[apPVRA] %s\n", ret.message);
        return ret;
    }
    int index = geo_time_index(*CI);
    if (index == -1) {
        ret.error = 2;
        sprintf(ret.message, "location not valid");
        printf("[apPVRA] %s\n", ret.message);
        return ret;
    }


    int num_data =  enclave_state->appdata.num_data;
    printf("[apPVRA] num_data %d\n", num_data);


    memcpy(&enclave_state->appdata.user_data[enclave_state->appdata.num_data], CI, sizeof(struct cInputs));
    enclave_state->appdata.num_data+=1;

    sprintf(ret.message, "success addPersonalData");
    printf("[apPVRA] %s\n", ret.message);
    return ret;
}

int geo_time_index(struct cInputs geo_time)
{
    printf("geo_time.lat %f geo_time.lng %f ",geo_time.lat, geo_time.lng);
    if (geo_time.lat < LAT_HEATMAP_MIN || geo_time.lat > LAT_HEATMAP_MAX || geo_time.lng < LONG_HEATMAP_MIN || geo_time.lng > LONG_HEATMAP_MAX ){
        printf("LAT_HEATMAP_MIN %f LAT_HEATMAP_MAX %f LONG_HEATMAP_MIN %f LONG_HEATMAP_MAX %f \n",LAT_HEATMAP_MIN, LAT_HEATMAP_MAX, LONG_HEATMAP_MIN, LONG_HEATMAP_MAX);
        return -1;
    }
    float side_length_lat = HEATMAP_GRANULARITY/(LAT_HEATMAP_MAX- LAT_HEATMAP_MIN);
    float side_length_long = HEATMAP_GRANULARITY/(LONG_HEATMAP_MAX- LONG_HEATMAP_MIN);
    int lat = ((geo_time.lat - LAT_HEATMAP_MIN)*side_length_lat);
    int lng = ((geo_time.lng - LONG_HEATMAP_MIN)*side_length_long);
    printf("geo_time_index %d\n",lat*HEATMAP_GRANULARITY + lng);
   return lat*HEATMAP_GRANULARITY + lng;
}

/* COMMAND1 Kernel Definition */
struct cResponse getHeatMap(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    struct cResponse ret;
    ret.error = 0;
    memset(ret.heatmap_data, 0, sizeof(ret.heatmap_data));
    memset(ret.message, 0, 100);

    for (int i = 0; i < enclave_state->appdata.num_data; i++) {
        struct cInputs data = enclave_state->appdata.user_data[i];
        if (data.result) {
            int heatmap_index = geo_time_index(data);
            if (heatmap_index >= 0) {
                ret.heatmap_data[heatmap_index]++;
                printf("inc bin %d %d\n", heatmap_index, ret.heatmap_data[heatmap_index]);
            }
        }
    }

    for (int i = 0; i < HEATMAP_GRANULARITY*HEATMAP_GRANULARITY; i++) {
        if (ret.heatmap_data[i] < HEATMAP_COUNT_THRESHOLD) {
            printf("below threshold %d %d\n",i, ret.heatmap_data[i]);
            ret.heatmap_data[i] = 0;
        }
    }
    sprintf(ret.message, "success getHeatMap");
    printf("[apPVRA] %s\n", ret.message);
    return ret;
}



/* Initializes the Function Pointers to Function Names Above */
int initFP(struct cResponse (*functions[NUM_COMMANDS+NUM_ADMIN_COMMANDS])(struct ES*, struct cInputs*, uint32_t uidx))
{
    (functions[0]) = &addPersonalData;
    (functions[1]) = &getHeatMap; //admin
    //printf("Initialized Application Kernels\n");
    return 0;
}


/* Initializes the Application Data as per expectation */
int initES(struct ES* enclave_state, struct dAppData *dAD)
{
    char *user_info = calloc(NUM_USERS*PUBLIC_KEY_SIZE,sizeof(char));
    if(user_info == NULL) return -1;

    struct cInputs *user_data = calloc(NUM_USERS*MAX_DATA,sizeof(struct cInputs));
    if(user_data == NULL) return -1;

    enclave_state->appdata.user_info = user_info;
    enclave_state->appdata.user_data = user_data;

    enclave_state->appdata.num_data = 0;


    /* Initialize metadata regarding dynamic data-structures for sealing purposes */

    // Number of dynamic data structures
    dAD->num_dDS = 2;

    // For each dDS, assign the pointer and the size of the DS
    struct dynamicDS *tDS = (struct dynamicDS *)calloc(1, sizeof(struct dynamicDS));
    if(tDS == NULL) return -1;
    tDS->buffer = user_info;
    tDS->buffer_size = NUM_USERS*PUBLIC_KEY_SIZE*sizeof(char);

    struct dynamicDS *nDS = (struct dynamicDS *)calloc(1, sizeof(struct dynamicDS));
    if(nDS == NULL) return -1;
    nDS->buffer = user_data;
    nDS->buffer_size = NUM_USERS*MAX_DATA*sizeof(struct cInputs);

    struct dynamicDS **dDS = (struct dynamicDS **)calloc(dAD->num_dDS, sizeof(struct dynamicDS *));
    if(dDS == NULL) return -1;
    dDS[0] = tDS;
    dDS[1] = nDS;
    dAD->dDS = dDS;
    return 0;
}

int initAD(struct ES* enclave_state, struct dAppData *dAD)
{
    enclave_state->appdata.user_info = dAD->dDS[0]->buffer;
    enclave_state->appdata.user_data = dAD->dDS[1]->buffer;
    return 0;
}


/* Debug Print Statement to Visualize clientCommands */
void print_clientCommand(struct clientCommand *CC, uint32_t uidx){
  printf("[apPVRA] Readable eCMD: {[CT]:%d [CI]:%d:[%d][%f,%f,%d,%d,%d] [SN]:%d}\n", CC->eCMD.CT, uidx, geo_time_index(CC->eCMD.CI), CC->eCMD.CI.lat, CC->eCMD.CI.lng, CC->eCMD.CI.startTs, CC->eCMD.CI.endTs, CC->eCMD.CI.result, CC->eCMD.seqNo);
}

