#include "enclave_state.h"
#include "appPVRA.h"


float LAT_HEATMAP_MAX = 40.25;
float LAT_HEATMAP_MIN = 39.5;
float LONG_HEATMAP_MAX = 116.75;
float LONG_HEATMAP_MIN = 116.0;
int HEATMAP_COUNT_THRESHOLD = 2;

/* COMMAND0 Kernel Definition */
struct cResponse addPersonalData(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    if(DEBUGPRINT) printf("[hm] addPersonalData uidx %d\n", uidx);
    struct cResponse ret;
    ret.error = 0;
    memset(ret.heatmap_data, 0, sizeof(ret.heatmap_data));
    memset(ret.message, 0, 100);

    if (enclave_state->appdata.num_data > MAX_DATA) {
        ret.error = 1;
        sprintf(ret.message, "data buffer already full");
        printf("[hm] %s\n", ret.message);
        return ret;
    }
    int index = geo_time_index(*CI);
    if (index == -1) {
        ret.error = 2;
        sprintf(ret.message, "location not valid");
        printf("[hm] %s\n", ret.message);
        return ret;
    }


    int num_data =  enclave_state->appdata.num_data;


    memcpy(&enclave_state->appdata.user_data[enclave_state->appdata.num_data], CI, sizeof(struct cInputs));
    enclave_state->appdata.num_data+=1;

    sprintf(ret.message, "success addPersonalData");
    if(DEBUGPRINT) printf("[hm] %s\n", ret.message);
    return ret;
}

int geo_time_index(struct cInputs geo_time)
{
    if(DEBUGPRINT) printf("[hm] geo_time.lat %f geo_time.lng %f ",geo_time.lat, geo_time.lng);
    if (geo_time.lat < LAT_HEATMAP_MIN || geo_time.lat > LAT_HEATMAP_MAX || geo_time.lng < LONG_HEATMAP_MIN || geo_time.lng > LONG_HEATMAP_MAX ){
        printf("\n[hm] error geo_time_index out of range\n");
        return -1;
    }
    float side_length_lat = HEATMAP_GRANULARITY/(LAT_HEATMAP_MAX- LAT_HEATMAP_MIN);
    float side_length_long = HEATMAP_GRANULARITY/(LONG_HEATMAP_MAX- LONG_HEATMAP_MIN);
    int lat = ((geo_time.lat - LAT_HEATMAP_MIN)*side_length_lat);
    int lng = ((geo_time.lng - LONG_HEATMAP_MIN)*side_length_long);
    if(DEBUGPRINT) printf("[hm] geo_time_index %d\n",lat*HEATMAP_GRANULARITY + lng);
   return lat*HEATMAP_GRANULARITY + lng;
}

/* COMMAND1 Kernel Definition */
struct cResponse getHeatMap(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    struct cResponse ret;
    ret.error = 0;
    memset(ret.heatmap_data, 0, sizeof(ret.heatmap_data));
    memset(ret.message, 0, 100);

    time_t curr_time;
    int err = get_timestamp(&curr_time);
    if (err != 0) {
        sprintf(ret.message, "get_timestamp failed");
        printf("[hm] %s\n", ret.message);
        ret.error = 1;
        return ret;
    }
    time_t diff = curr_time - enclave_state->appdata.last_hm_time;
    if (enclave_state->appdata.last_hm_time != 0 && diff < RESET_TIME) {
        sprintf(ret.message, "must wait %ld seconds before creating heatmap", RESET_TIME - diff);
        printf("[hm] %s\n", ret.message);
        ret.error = 2;
        return ret;
    }

    for (int i = 0; i < enclave_state->appdata.num_data; i++) {
        struct cInputs data = enclave_state->appdata.user_data[i];
        if (data.result) {
            int heatmap_index = geo_time_index(data);
            if (heatmap_index >= 0) {
                ret.heatmap_data[heatmap_index]++;
            }
        }
    }

    for (int i = 0; i < HEATMAP_GRANULARITY*HEATMAP_GRANULARITY; i++) {
        if (ret.heatmap_data[i] < HEATMAP_COUNT_THRESHOLD) {
            ret.heatmap_data[i] = 0;
        }
    }
    enclave_state->appdata.num_data = 0;
    enclave_state->appdata.last_hm_time = curr_time;
    sprintf(ret.message, "success getHeatMap");
    if(DEBUGPRINT) printf("[apPVRA] %s\n", ret.message);
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

//todo add validation on users
/* Initializes the Application Data as per expectation */
int initES(struct ES* enclave_state, struct dAppData *dAD, uint64_t num_users, bool dry_run)
{
    size_t user_data_size = num_users*MAX_DATA*sizeof(locationData);
    enclave_state->appdata.user_data = (locationData *) malloc(user_data_size);
    if(enclave_state->appdata.user_data == NULL) return -1;

    enclave_state->appdata.num_data = 0;
    enclave_state->appdata.last_hm_time = 0;
    /* Initialize metadata regarding dynamic data-structures for sealing purposes */

    // Number of dynamic data structures
    dAD->num_dDS = 1;
    struct dynamicDS *dDS = (struct dynamicDS *)malloc(dAD->num_dDS*sizeof(struct dynamicDS));
    if(dDS == NULL) return -1;
    dDS[0].buffer = enclave_state->appdata.user_data;
    dDS[0].buffer_size = user_data_size;
    dAD->dDS = dDS;
    return 0;
}

int initAD(struct ES* enclave_state, struct dAppData *dAD)
{
    enclave_state->appdata.user_data = dAD->dDS[0].buffer;
    return 0;
}

void formatResponse(struct cResponse *ret, int error, char * message) {
    ret->error = error;
    memset(ret->heatmap_data, 0, sizeof(ret->heatmap_data));
    memcpy(ret->message, message, 100);
}


/* Debug Print Statement to Visualize clientCommands */
void print_clientCommand(struct clientCommand *CC, uint32_t uidx){
  printf("[apPVRA] Readable eCMD: {[CT]:%d [CI]:%d:[%d][%f,%f,%d,%d,%d] [SN]:%lu}\n", CC->eCMD.CT, uidx, geo_time_index(CC->eCMD.CI), CC->eCMD.CI.lat, CC->eCMD.CI.lng, CC->eCMD.CI.startTs, CC->eCMD.CI.endTs, CC->eCMD.CI.result, CC->seqNo);
}

