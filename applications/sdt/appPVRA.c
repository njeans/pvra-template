#include <mbedtls/aes.h>

#include "enclavestate.h"
#include "appPVRA.h"
#include "merkletree.h"

/* COMMAND0 Kernel Definition */
struct cResponse addPersonalData(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    printf("[apPVRA] addPersonalData %d\n", uidx);
    struct cResponse ret;
    memset(ret.output_data, 0, DATA_SIZE);
    memset(ret.message, 0, 100);
    ret.error = 0;

    memcpy(enclave_state->appdata.user_info[uidx].secret_data, CI->input_data, DATA_SIZE);
    sprintf(ret.message, "success addPersonalData");
    printf("[apPVRA] %s\n", ret.message);
    return ret;
}

struct cResponse getPersonalData(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    printf("[apPVRA] getPersonalData %d\n", uidx);
    struct cResponse ret;
    ret.error = 0;
    memset(ret.output_data, 0, DATA_SIZE);
    memset(ret.message, 0, 100);

    memcpy(ret.output_data, enclave_state->appdata.user_info[uidx].secret_data, sizeof(enclave_state->appdata.user_info[uidx].secret_data));
    sprintf(ret.message, "success getPersonalData");
    printf("[apPVRA] %s\n", ret.message);
    return ret;
}

/* COMMAND1 Kernel Definition */
struct cResponse startRetrieve(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    printf("[sdt] startRetrieve\n");
    struct cResponse ret;
    ret.error = 0;
    memset(ret.output_data, 0, DATA_SIZE);
    memset(ret.message, 0, 100);

    int user_idx = -1;
    for(int i = 1; i < NUM_USERS+1; i++) {
        if(strncmp(&CI->user_pubkey, &enclave_state->auditmetadata.master_user_pubkeys[i], sizeof(secp256k1_pubkey)) == 0) {
          user_idx = i-1;
          break;
        }
    }

    if (user_idx == -1) {
         sprintf(ret.message, "[apPVRA] invalid user public key");
         printf("%s\n", ret.message);
         ret.error = 1;
         return ret;
    }

    printf("[apPVRA startRetrieve %d\n", user_idx);


    if (enclave_state->appdata.retrieve_count >= MAX_RETRIEVE) {
        sprintf(ret.message, "retrieve_count limit reached %d > %d", enclave_state->appdata.retrieve_count, MAX_RETRIEVE);
        printf("[apPVRA] %s\n", ret.message);
        ret.error = 3;
        return ret;
    }
    struct userInfo ui = enclave_state->appdata.user_info[user_idx];
    if (ui.started_retrieve) {
        sprintf(ret.message, "retrieval already started");
        printf("[apPVRA] %s\n", ret.message);
        ret.error = 4;
        return ret;
    }
    enclave_state->appdata.user_info[user_idx].retrieve_count++; // todo delete?
    enclave_state->appdata.user_info[user_idx].retrieve_time = WAIT_TIME + 10 + user_idx;//get_timestamp();
    enclave_state->appdata.user_info[user_idx].started_retrieve = true;
    enclave_state->appdata.retrieve_count++;
    sprintf(ret.message, "success startRetrieve");
    printf("[apPVRA] %s\n", ret.message);
    return ret;
}

/* COMMAND2 Kernel Definition */
struct cResponse completeRetrieve(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    printf("[apPVRA] completeRetrieve\n");
    struct cResponse ret;
    ret.error = 0;
    memset(ret.output_data, 0, DATA_SIZE);
    memset(ret.message, 0, 100);

    printf("[apPVRA] new user_pubkey\n");
    print_hexstring_n(&CI->user_pubkey, 3);
    printf("..");
    print_hexstring_n(((char *)&CI->user_pubkey)+61, 3);
    printf("\n");

    int user_idx = -1;
    for(int i = 1; i < NUM_USERS+1; i++) {
        if(strncmp(&CI->user_pubkey, &enclave_state->auditmetadata.master_user_pubkeys[i], sizeof(secp256k1_pubkey)) == 0) {
          user_idx = i-1;
          break;
        }
    }
    if (user_idx == -1) {
         sprintf(ret.message, "invalid user public key");
         printf("[apPVRA] %s\n", ret.message);
         ret.error = 1;
         return ret;
    }
    printf("[apPVRA] completeRetrieve uidx %d\n", user_idx);
    struct userInfo ui = enclave_state->appdata.user_info[user_idx];
    if (!ui.started_retrieve) {
        sprintf(ret.message, "retrieval not started");
        printf("[apPVRA] %s\n", ret.message);
        ret.error = 4;
        return ret;
    }

    uint32_t curr = 71;//get_timestamp() TODO
    if (curr < ui.retrieve_time) {
        sprintf(ret.message, "retrieval wait period not over %u < %u", curr, ui.retrieve_time);
        printf("[apPVRA] %s\n", ret.message);
        ret.error = 5;
        return ret;
    }

    memcpy(&enclave_state->auditmetadata.master_user_pubkeys[user_idx+1], &CI->recover_key, KEY_SIZE);
    enclave_state->appdata.user_info[user_idx].started_retrieve = false;
    enclave_state->appdata.user_info[user_idx].retrieve_time = 0;

    sprintf(ret.message, "success completeRetrieve");
    printf("[apPVRA] %s\n", ret.message);
    return ret;
}

/* COMMAND3 Kernel Definition */
struct cResponse cancelRetrieve(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    printf("[apPVRA] cancelRetrieve %d\n", uidx);

    struct cResponse ret;
    memset(ret.output_data, 0, DATA_SIZE);
    memset(ret.message, 0, 100);
    ret.error = 0;

    if (!enclave_state->appdata.user_info[uidx].started_retrieve) {
        sprintf(ret.message, "retrieval not started");
        printf("[apPVRA] %s\n", ret.message);
        ret.error = 7;
        return ret;
    }
    ret.error = 0;
    enclave_state->appdata.user_info[uidx].started_retrieve = false;
    enclave_state->appdata.user_info[uidx].retrieve_time = 0;
    sprintf(ret.message, "success cancelRetrieve");
    printf("[apPVRA] %s\n", ret.message);
    return ret;
}

#ifdef MERKLE_TREE
size_t get_user_leaf(struct ES *enclave_state, char ** out) {
    printf("[apPVRA] get_user_leaf\n");
    size_t block_size = sizeof(struct userLeaf);
    for (int i=0; i< NUM_USERS; i++) {
        out[i] = (char *) malloc(block_size);
        struct userInfo info = enclave_state->appdata.user_info[i];
        struct userLeaf leaf = {info.retrieve_count, info.retrieve_time, info.started_retrieve, i};
        memcpy(out[i], &leaf, block_size);
//        memcpy_big_uint32(out[i], info.retrieve_count) todo
        printf("[apPVRA] uidx %d: rc %d rt %d sr %d ", i, enclave_state->appdata.user_info[i].retrieve_count, enclave_state->appdata.user_info[i].retrieve_time, enclave_state->appdata.user_info[i].started_retrieve);
        print_hexstring(out[i], block_size);
    }
    return block_size;
}
#endif



/* Initializes the Function Pointers to Function Names Above */
int initFP(struct cResponse (*functions[NUM_COMMANDS+NUM_ADMIN_COMMANDS])(struct ES*, struct cInputs*, uint32_t)){
    (functions[0]) = &addPersonalData;
    (functions[1]) = &cancelRetrieve;
    (functions[2]) = &getPersonalData;

    (functions[3]) = &startRetrieve; //admin
    (functions[4]) = &completeRetrieve; //admin

    //printf("Initialized Application Kernels\n");
    return 0;
}


/* Initializes the Application Data as per expectation */
int initES(struct ES* enclave_state, struct dAppData *dAD)
{
    for (int i = 0; i < NUM_USERS; i++) {
        enclave_state->appdata.user_info[i].started_retrieve = false;
        enclave_state->appdata.user_info[i].retrieve_time = 0;
        enclave_state->appdata.user_info[i].retrieve_count = 0;
        memset(enclave_state->appdata.user_info[i].secret_data, 0, DATA_SIZE);
    }
    enclave_state->appdata.retrieve_count = 0;
    enclave_state->appdata.last_reset_time = 0;
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
//
    return 0;
}

int initAD(struct ES* enclave_state, struct dAppData *dAD)
{
//    enclave_state->appdata.user_info = dAD->dDS[0]->buffer;
//    enclave_state->appdata.retrieve_list = dAD->dDS[1]->buffer;
//
    return 0;
}


/* Debug Print Statement to Visualize clientCommands */
void print_clientCommand(struct clientCommand *CC, uint32_t uidx){
  printf("[apPVRA] Readable eCMD: {[CT]:%d [uidx]: %d [CI]:[", CC->eCMD.CT, uidx);
  print_hexstring_n(CC->eCMD.CI.input_data, 3);
  printf("...");
  print_hexstring_n(CC->eCMD.CI.input_data+(DATA_SIZE-3), 3);
  printf(", ");
  print_hexstring_n(CC->eCMD.CI.recover_key , 3);
  printf("...");
  print_hexstring_n(CC->eCMD.CI.recover_key+(KEY_SIZE-3) , 3);
  printf("] [SN]:%d}\n", CC->seqNo);
}

