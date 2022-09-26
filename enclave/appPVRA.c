#include "enclavestate.h"
#include "appPVRA.h"

int LAT_MAX = 10;
int LAT_MIN = 1;
int LONG_MAX = 5;
int LONG_MIN = 1;
int HEATMAP_COUNT_THRESHOLD = 2;

/* COMMAND0 Kernel Definition */
struct cResponse addPersonalData(struct ES *enclave_state, struct cInputs *CI)
{
    struct cResponse ret;

    //printf("[apPVRA] Readable eCMD: [CI]:%d,%d} ", CI->uid, CI->test_result);

    if(CI->uid > NUM_USERS-1) {
        char *m = "[apPVRA] STATUS_UPDATE ERROR invalid userID";
        printf("%s\n", m);
        memcpy(ret.error_message, m, strlen(m)+1);
        ret.error = 1;
        return ret;
    }

    ret.error = 0;
    char *m = "[apPVRA] STATUS_UPDATE SAVED location data";
    //printf("%s %d %d %d %d\n", m, enclave_state->appdata.test_history[CI->uid*NUM_TESTS + enclave_state->appdata.num_tests[CI->uid]], enclave_state->appdata.num_tests[CI->uid], enclave_state->appdata.query_counter[CI->uid], CI->test_result);
    memcpy(ret.error_message, m, strlen(m)+1);

    int num_data =  enclave_state->appdata.num_data;
    for (int i = 0; i < CI->num_data; i++) {
        enclave_state->appdata.user_data[num_data+i] = CI->data[i];
    }
    enclave_state->appdata.num_data+=CI->num_data;

    return ret;
}

int geo_time_index(struct locationData geo_time)
{
//    println!("geo_time_index geo_time.lat {:?} geo_time.lng {:?}",geo_time.lat,geo_time.lng);
    if (geo_time.lat < LAT_MIN || geo_time.lat > LAT_MAX || geo_time.lng < LONG_MIN || geo_time.lng > LONG_MAX ){
        return -1;
    }
    float side_length_lat = HEATMAP_GRANULARITY/(LAT_MAX- LAT_MIN);
    float side_length_long = HEATMAP_GRANULARITY/(LONG_MAX- LONG_MIN);
    int lat = ((geo_time.lat - LAT_MIN)*side_length_lat);//.round();//TODO round function?
    int lng = ((geo_time.lng - LONG_MIN)*side_length_long);//.round();//TODO round function?
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
                ret.heatmap[heatmap_index]++;
            }
        }
    }

    for (int i = 0; i < HEATMAP_GRANULARITY*HEATMAP_GRANULARITY; i++) {
        if (ret.heatmap[i] < HEATMAP_COUNT_THRESHOLD) {
            ret.heatmap[i] = 0;
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
int initES(struct ES* enclave_state)
{
    enclave_state->appdata.num_data = 0;
    return 0;
}


/* Debug Print Statement to Visualize clientCommands */
void print_clientCommand(struct clientCommand *CC){
  printf("[apPVRA] Readable eCMD: {[CT]:%d [CI]:%d,%d [SN]:%d [ID]:%d} ", CC->CT.tid, CC->CI.uid, CC->CI.num_data, CC->seqNo, CC->cid);
}

