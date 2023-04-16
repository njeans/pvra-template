#include "enclave_state.h"
#include "appPVRA.h"
#include <math.h>

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
    sprintf(ret.message, "success getHeatMap");
    if(DEBUGPRINT) printf("[apPVRA] %s\n", ret.message);
    return ret;
}

int Hash_DRBG_Instantiate_algorithm(struct DRBG * drgb_state, uint8_t entropy_input[SECURITY_STRENGTH], uint8_t nonce[SECURITY_STRENGTH/2], char * personalization_string) {
    drgb_state->counter = 1;
    size_t seed_material_len = 2*SECURITY_STRENGTH + strlen(personalization_string);
    uint8_t *seed_material = (uint8_t *) malloc(seed_material_len+1);
    memset(seed_material, 0, seed_material_len+1);
    memcpy(seed_material + 1, entropy_input, SECURITY_STRENGTH);
    memcpy(seed_material + 1 + SECURITY_STRENGTH, nonce, SECURITY_STRENGTH);
    memcpy(seed_material + 1 + 2*SECURITY_STRENGTH, personalization_string, strlen(personalization_string));
    sha256(seed_material + 1, seed_material_len, drgb_state->value);
    memcpy(seed_material + 1, drgb_state->value, seed_material_len-1);
    sha256(seed_material, seed_material_len, drgb_state->constant);
    free(seed_material);
    return 0;
}

//todo lookup SP 800-57
int Hash_DRBG_Reseed_algorithm(struct DRBG * drgb_state, uint8_t entropy_input[SEEDLEN], uint8_t additional_input[HASH_SIZE]) {
    size_t seed_material_len = 1 + HASH_SIZE + SEEDLEN + HASH_SIZE;
    uint8_t *seed_material = (uint8_t *) malloc(seed_material_len);
    seed_material[0] = 1;
    memcpy(seed_material + 1, drgb_state->value, HASH_SIZE);
    memcpy(seed_material + 1 + HASH_SIZE, entropy_input, SEEDLEN);
    memcpy(seed_material + 1 + HASH_SIZE + SEEDLEN, additional_input, HASH_SIZE);
    sha256(seed_material, seed_material_len, drgb_state->value);
    uint8_t concat[1+HASH_SIZE] = {0};
    memcpy(concat + 1, drgb_state->value, HASH_SIZE);
    sha256(concat, 1+HASH_SIZE, drgb_state->constant);
    drgb_state->counter = 1;
    return 0;
}

void Hashgen(uint8_t V[HASH_SIZE], uint8_t *returned_bits, size_t requested_number_of_bits) {
    size_t m = 1 + requested_number_of_bits/HASH_SIZE;
    uint8_t data[HASH_SIZE];
    uint8_t w[HASH_SIZE];
    uint8_t *W = returned_bits;
    memset(W, 0, requested_number_of_bits);
    size_t W_len = 0;
    memcpy(data, V, HASH_SIZE);
    for(size_t i = 1; i <= m; i++) {
        sha256(data, HASH_SIZE, w);
        size_t copy_len = min(requested_number_of_bits - W_len, HASH_SIZE);
        memcpy(W + W_len, w, copy_len);
        W_len += copy_len;
    }
}

int Hash_DRBG_Generate_algorithm(struct DRBG * drgb_state, uint8_t additional_input[HASH_SIZE], uint8_t *returned_bits, size_t requested_number_of_bits) {
    sgx_status_t ret1 = 0;
    int ret2 = 0;
    uint8_t H[HASH_SIZE+1];
    if (drgb_state->counter > RESEED_INTERVAL) {
        uint8_t entropy_input[SECURITY_STRENGTH];
         ret1 = sgx_read_rand(entropy_input, sizeof(entropy_input));
        if (ret1 != SGX_SUCCESS) {
            printf("[hm] sgx_read_rand error\n");
            return -1;
        }
        ret2 = Hash_DRBG_Reseed_algorithm(drgb_state, entropy_input, additional_input);
        if (ret2 != 0) {
            printf("[hm] Hash_DRBG_Reseed_algorithm error\n");
            return -1;
        }

    }
    uint8_t w[1+2*HASH_SIZE] = {0};
    w[0] = 2;
    memcpy(w+1, drgb_state->value, HASH_SIZE);
    memcpy(w+1+HASH_SIZE, additional_input, HASH_SIZE);
    /* todo 
    drgb_state->value = (drgb_state->value + w) mod 2**seedlen
    HASHgen(drgb_state->value, returned_bits, requested_number_of_bits)

    */
    H[0] = 3;
    //drgb_state->value = (drgb_state->value+H+drgb_state->constant+drgb_state->value) mod 2**seedlen
    drgb_state->counter += 1;
    return 0;
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

    if (!dry_run) {
        uint8_t entropy_input[SECURITY_STRENGTH], nonce[SECURITY_STRENGTH/2];
        char * datetime;
        sgx_status_t ret = sgx_read_rand(entropy_input, sizeof(entropy_input));
        if (ret != SGX_SUCCESS) {
            printf("[hm] sgx_read_rand error\n");
            return -1;
        }
        ret = sgx_read_rand(nonce, sizeof(nonce));
        if (ret != SGX_SUCCESS) {
            printf("[hm] sgx_read_rand error\n");
            return -1;
        }
       int err = get_timestamp_str(datetime);
       if (err != 0) {
            printf("[hm] get_timestamp_str error\n");
            return -1;        
       }
        Hash_DRBG_Instantiate_algorithm(enclave_state->random_gen, entropy_input, nonce, datetime);
    } else {
        enclave_state->random_gen.value = {0};
        enclave_state->random_gen.constant =  {0};
        enclave_state->random_gen.counter = 0;
    }

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

