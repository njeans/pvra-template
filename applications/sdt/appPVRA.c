#include <mbedtls/aes.h>

#include "enclavestate.h"
#include "appPVRA.h"
#include "merkletree.h"

/* COMMAND0 Kernel Definition */
struct cResponse addPersonalData(struct ES *enclave_state, struct cInputs *CI)
{
    printf("[sdt] addPersonalData\n");
    struct cResponse ret;
    ret.error = 0;

    if(CI->uidx >= NUM_USERS) {
        sprintf(ret.message, "[apPVRA] invalid uid %d > %d", CI->uidx, NUM_USERS-1);
        printf("%s\n", ret.message);
        ret.error = 1;
        return ret;
    }
    struct userInfo ui;
    ui.uidx = CI->uidx;
    ui.retrieve_count = 0;
    ui.retrieve_time = 0;
    ui.started_retrieve = false;
    memcpy(ui.secret_data, CI->input_data, DATA_SIZE);
    enclave_state->appdata.user_info[CI->uidx] =  ui;
    sprintf(ret.message, "success addPersonalData");
    return ret;
}

/* COMMAND1 Kernel Definition */
struct cResponse startRetrieve(struct ES *enclave_state, struct cInputs *CI)
{
    printf("[sdt] startRetrieve\n");
    struct cResponse ret;
    ret.error = 0;
    if (enclave_state->appdata.retrieve_count >= MAX_RETRIEVE) {
        sprintf(ret.message, "[apPVRA] retrieve_count %d >= %d", enclave_state->appdata.retrieve_count, MAX_RETRIEVE);
        printf("%s\n", ret.message);
        ret.error = 2;
        return ret;
    }
    struct userInfo ui = enclave_state->appdata.user_info[CI->uidx];
    if (ui.started_retrieve) {
        sprintf(ret.message, "[apPVRA] retrieval already started");
        printf("%s\n", ret.message);
        ret.error = 3;
        return ret;
    }
    enclave_state->appdata.user_info[CI->uidx].retrieve_count++;
    enclave_state->appdata.user_info[CI->uidx].retrieve_time = 10 + WAIT_TIME;;//get_timestamp();
    enclave_state->appdata.user_info[CI->uidx].started_retrieve = true;
    sprintf(ret.message, "success startRetrieve");
    return ret;
}

/* COMMAND2 Kernel Definition */
struct cResponse completeRetrieve(struct ES *enclave_state, struct cInputs *CI)
{
    printf("[sdt] completeRetrieve\n");
    struct cResponse ret;
    ret.error = 0;
    int err;
    struct userInfo ui = enclave_state->appdata.user_info[CI->uidx];
    if (!ui.started_retrieve) {
        sprintf(ret.message, "[apPVRA] retrieval not yet started");
        printf("%s\n", ret.message);
        ret.error = 4;
        return ret;
    }
    int curr = 71;//get_timestamp() TODO
    if (curr < ui.retrieve_time) {
        sprintf(ret.message, "[apPVRA] retrieval wait period not over");
        printf("%s\n", ret.message);
        ret.error = 5;
        return ret;
    }
//    mbedtls_aes_context *ctx;
//    mbedtls_aes_init(ctx);
//    err = mbedtls_aes_setkey_enc(ctx, &CI->recover_key, 256);
//    if( err != 0) {
//        sprintf(ret.message, "[apPVRA] encryption error");
//        printf("%s\n", ret.message);
//        ret.error = 6;
//        mbedtls_aes_free(ctx);
//        return ret;
//    }
//    size_t nc_off = 0;
//    unsigned char nonce_counter[16] = "nonce_counter<3 ";
//    unsigned char stream_block[16] =  "stream_block <3 ";
//    err = mbedtls_aes_crypt_ctr(ctx, DATA_SIZE, &nc_off, nonce_counter, stream_block,
//                                 &enclave_state->appdata.user_info[CI->uidx].secret_data,
//                                 &ret.output_data);
//    if (err != 0) {
//        sprintf(ret.message, "[apPVRA] encryption error");
//        printf("%s\n", ret.message);
//        ret.error = 6;
//        mbedtls_aes_free(ctx);
//        return ret;
//    }
//    mbedtls_aes_free(ctx);

    memcpy(&ret.output_data, &enclave_state->appdata.user_info[CI->uidx].secret_data, sizeof(enclave_state->appdata.user_info[CI->uidx].secret_data));

    enclave_state->appdata.user_info[CI->uidx].started_retrieve = false;
    enclave_state->appdata.user_info[CI->uidx].retrieve_time = 0;
    sprintf(ret.message, "success completeRetrieve");
    return ret;
}

/* COMMAND3 Kernel Definition */
struct cResponse cancelRetrieve(struct ES *enclave_state, struct cInputs *CI)
{
    printf("[sdt] cancelRetrieve\n");
    struct cResponse ret;
    int err;
    ret.error = 0;
    struct userInfo ui = enclave_state->appdata.user_info[CI->uidx];
    if (!ui.started_retrieve) {
        sprintf(ret.message, "[apPVRA] retrieval not started");
        printf("%s\n", ret.message);
        ret.error = 7;
        return ret;
    }
    sprintf(ret.message, "[apPVRA] retrieval canceled");
    printf("%s\n", ret.message);
    ret.error = 0;
    enclave_state->appdata.user_info[CI->uidx].started_retrieve = false;
    enclave_state->appdata.user_info[CI->uidx].retrieve_time = 0;
    sprintf(ret.message, "success cancelRetrieve");
    return ret;
}

void get_user_leaf(struct ES *enclave_state, char * out[NUM_USERS], int * block_size) {
    for (int i=0; i< NUM_USERS; i++) {
        out[i] = (char *)malloc(sizeof(struct userLeaf));
        struct userInfo info = enclave_state->appdata.user_info[i];
        struct userLeaf leaf = {info.retrieve_count, info.retrieve_time, info.started_retrieve};
        memcpy(out[i], &leaf, sizeof(struct userLeaf));
    }
    *block_size = sizeof(struct userLeaf);
}



/* Initializes the Function Pointers to Function Names Above */
int initFP(struct cResponse (*functions[NUM_COMMANDS])(struct ES*, struct cInputs*))
{
    (functions[0]) = &addPersonalData;
    (functions[1]) = &startRetrieve;
    (functions[2]) = &completeRetrieve;
    (functions[3]) = &cancelRetrieve;

    //printf("Initialized Application Kernels\n");
    return 0;
}


/* Initializes the Application Data as per expectation */
int initES(struct ES* enclave_state, struct dAppData *dAD)
{
//    struct userInfo * user_info = calloc(NUM_USERS,sizeof(struct userInfo));
//    if(user_info == NULL) return -1;

//    printf("calloc 0??\n");
//    int * retrieve_list = calloc(0,sizeof(int));
//    if(retrieve_list == NULL) return -1;

//    enclave_state->appdata.user_info = user_info;

//    enclave_state->appdata.num_data = 0;


    /* Initialize metadata regarding dynamic data-structures for sealing purposes */

    // Number of dynamic data structures
    dAD->num_dDS = 0;

    // For each dDS, assign the pointer and the size of the DS
//    struct dynamicDS *tDS = (struct dynamicDS *)calloc(1, sizeof(struct dynamicDS));
//    if(tDS == NULL) return -1;
//    tDS->buffer = user_info;
//    tDS->buffer_size = NUM_USERS*sizeof(struct userInfo);

//    struct dynamicDS *nDS = (struct dynamicDS *)calloc(1, sizeof(struct dynamicDS));
//    if(nDS == NULL) return -1;
//    nDS->buffer = retrieve_list;
//    nDS->buffer_size = 0;

    struct dynamicDS **dDS = (struct dynamicDS **)calloc(dAD->num_dDS, sizeof(struct dynamicDS *));
    if(dDS == NULL) return -1;
//    dDS[0] = nDS;
//    dDS[1] = tDS;
    dAD->dDS = dDS;
    return 0;
}

int initAD(struct ES* enclave_state, struct dAppData *dAD)
{
//    enclave_state->appdata.user_info = dAD->dDS[0]->buffer;
//    enclave_state->appdata.retrieve_list = dAD->dDS[1]->buffer;
    enclave_state->appdata.last_reset_time = 0;//todo get timestamp
    enclave_state->appdata.retrieve_count = 0;
    return 0;
}


/* Debug Print Statement to Visualize clientCommands */
void print_clientCommand(struct clientCommand *CC){
  printf("[apPVRA] Readable eCMD: {[CT]:%d [CI]:%d:[", CC->eCMD.CT.tid, CC->eCMD.CI.uidx);
  print_hexstring_n(CC->eCMD.CI.input_data, 3);
  printf("...");
  print_hexstring_n(CC->eCMD.CI.input_data+(DATA_SIZE-3), 3);
  printf(", ");
  print_hexstring_n(CC->eCMD.CI.recover_key , 3);
  printf("...");
  print_hexstring_n(CC->eCMD.CI.recover_key+(KEY_SIZE-3) , 3);
  printf("] [SN]:%d} ", CC->eCMD.seqNo);
}

