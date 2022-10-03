#include "enclavestate.h"
#include "appPVRA.h"

int LAT_HEATMAP_MAX = 10;
int LAT_HEATMAP_MIN = 1;
int LONG_HEATMAP_MAX = 5;
int LONG_HEATMAP_MIN = 1;
int HEATMAP_COUNT_THRESHOLD = 2;

/* COMMAND0 Kernel Definition */
struct cResponse addPersonalData(struct ES *enclave_state, struct cInputs *CI)
{
    struct cResponse ret;

    //printf("[apPVRA] Readable eCMD: [CI]:%d,%d} ", CI->uid, CI->test_result);

    if(CI->uid > NUM_USERS-1) {
        char *m = "[apPVRA] STATUS_UPDATE ERROR invalid userID";
        printf("%s\n", m);
        memcpy(ret.message, m, strlen(m)+1);
        ret.error = 1;
        return ret;
    }
    if (enclave_state->appdata.num_data > 1024) {
        ret.error = 1;
        char *m = "[apPVRA] STATUS_UPDATE ERROR data buffer already full";
        printf("%s\n", m);
        memcpy(ret.message, m, strlen(m)+1);
        return ret;
    }


    int num_data =  enclave_state->appdata.num_data;
//    for (int i = 0; i < CI->num_data; i++) {
//        enclave_state->appdata.user_data[num_data+i] = CI->data[i];
//    }

    printf("accessing user_data[%d] enclave_state struct %p CI struct %p\n",num_data, enclave_state->appdata.user_data, CI->data);
    memcpy(enclave_state->appdata.user_data, CI->data,sizeof(struct locationData));
    //enclave_state->appdata.user_data[num_data] = CI->data;//[i];
    printf("succesfully set appdata.user_data[]");
    enclave_state->appdata.num_data+=1;//CI->num_data;
    printf("succesfully set appdata.num_data %d ",enclave_state->appdata.num_data);

    ret.error = 0;
    char *m = "[apPVRA] STATUS_UPDATE SAVED location data";
    memcpy(ret.message, m, strlen(m)+1);
    return ret;
}

int geo_time_index(struct locationData geo_time)
{
//    println!("geo_time_index geo_time.lat {:?} geo_time.lng {:?}",geo_time.lat,geo_time.lng);
    if (geo_time.lat < LAT_HEATMAP_MIN || geo_time.lat > LAT_HEATMAP_MAX || geo_time.lng < LONG_HEATMAP_MIN || geo_time.lng > LONG_HEATMAP_MAX ){
        return -1;
    }
    float side_length_lat = HEATMAP_GRANULARITY/(LAT_HEATMAP_MAX- LAT_HEATMAP_MIN);
    float side_length_long = HEATMAP_GRANULARITY/(LONG_HEATMAP_MAX- LONG_HEATMAP_MIN);
    int lat = ((geo_time.lat - LAT_HEATMAP_MIN)*side_length_lat);//.round();//TODO round function?
    int lng = ((geo_time.lng - LONG_HEATMAP_MIN)*side_length_long);//.round();//TODO round function?
//    println!("geo_time_index side_length_lat {:?} side_length_long {:?}",side_length_lat,side_length_long);
//    println!("geo_time_index lat {:?} lng {:?}",lat,lng);
   return lat*HEATMAP_GRANULARITY + lng;
}

/* COMMAND1 Kernel Definition */
struct cResponse getHeatMap(struct ES *enclave_state, struct cInputs *CI)
{
    struct cResponse ret;
//    int data_size = sizeof(struct locationData);
    for (int i = 0; i < enclave_state->appdata.num_data; i++) {
        struct locationData data = enclave_state->appdata.user_data[i];
        if (data.result) {
            int heatmap_index = geo_time_index(data);
            if (heatmap_index > 0) {
                ret.heatmap_data[heatmap_index]++;
            }
        }
    }

    for (int i = 0; i < HEATMAP_GRANULARITY*HEATMAP_GRANULARITY; i++) {
        if (ret.heatmap_data[i] < HEATMAP_COUNT_THRESHOLD) {
            ret.heatmap_data[i] = 0;
        }
    }
    return ret;
}



/* Initializes the Function Pointers to Function Names Above */
int initFP(struct cResponse (*functions[NUM_COMMANDS])(struct ES*, struct cInputs*)) 
{
    (functions[0]) = &addPersonalData;
    (functions[1]) = &getHeatMap;
    //printf("Initialized Application Kernels\n");
    return 0;
}


/* Initializes the Application Data as per expectation */
int initES(struct ES* enclave_state, struct dAppData *dAD)
{
    char *user_info = calloc(NUM_USERS*PUBLIC_KEY_SIZE,sizeof(char));
    if(user_info == NULL) return -1;

    struct locationData *user_data = calloc(NUM_USERS*MAX_DATA,sizeof(struct locationData));
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
    nDS->buffer_size = NUM_USERS*MAX_DATA*sizeof(struct locationData);

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
void print_clientCommand(struct clientCommand *CC){
  printf("[apPVRA] Readable eCMD: {[CT]:%d [CI]:%d:[%f,%f,%d,%d,%d] [SN]:%d [ID]:%d} ", CC->CT.tid, CC->CI.uid, CC->CI.data.lat, CC->CI.data.lng, CC->CI.data.startTs, CC->CI.data.endTs, CC->CI.data.result, CC->seqNo, CC->cid);
}

