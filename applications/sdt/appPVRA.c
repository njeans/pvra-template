#include "enclave_state.h"
#include "appPVRA.h"
#include "util.h"

time_t reset_data(struct ES *enclave_state) {
    time_t curr_time;
    int err = get_timestamp(&curr_time);
    if (err != 0) {
        return 0;
    }
    if (curr_time - enclave_state->appdata.last_reset_time >= RESET_TIME) {
        if(DEBUGPRINT) printf("[sdt] reseting retrieve counts\n");
        while(enclave_state->appdata.last_reset_time + RESET_TIME <= curr_time)
            enclave_state->appdata.last_reset_time += RESET_TIME;
        enclave_state->appdata.retrieve_count = 0;
    }
    return curr_time;
}

/* COMMAND0 Kernel Definition */
struct cResponse addPersonalData(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    if(DEBUGPRINT) printf("[sdt] addPersonalData uidx %d\n", uidx);
    struct cResponse ret;
    memset(ret.output_data, 0, DATA_SIZE);
    memset(ret.message, 0, 100);
    ret.error = 0;
    time_t curr_time = reset_data(enclave_state);
    if (curr_time == 0) {
        sprintf(ret.message, "reset_data failed");
        printf("[sdt] %s\n", ret.message);
        ret.error = 1;
        return ret;
    }
    memcpy(enclave_state->appdata.user_info[uidx].secret_data, CI->input_data, DATA_SIZE);
    sprintf(ret.message, "success addPersonalData");
    if(DEBUGPRINT) printf("[sdt] %s\n", ret.message);
    return ret;
}

struct cResponse getPersonalData(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    if(DEBUGPRINT) printf("[sdt] getPersonalData uidx  %d\n", uidx);
    struct cResponse ret;
    ret.error = 0;
    memset(ret.output_data, 0, DATA_SIZE);
    memset(ret.message, 0, 100);
    time_t curr_time = reset_data(enclave_state);
    if (curr_time == 0) {
        sprintf(ret.message, "reset_data failed");
        printf("[sdt] %s\n", ret.message);
        ret.error = 1;
        return ret;
    }
    memcpy(ret.output_data, enclave_state->appdata.user_info[uidx].secret_data, sizeof(enclave_state->appdata.user_info[uidx].secret_data));
    sprintf(ret.message, "success getPersonalData");
    if(DEBUGPRINT) printf("[sdt] %s\n", ret.message);
    return ret;
}

/* COMMAND1 Kernel Definition */
struct cResponse startRetrieve(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    if(DEBUGPRINT) printf("[sdt] startRetrieve\n");
    struct cResponse ret;
    ret.error = 0;
    memset(ret.output_data, 0, DATA_SIZE);
    memset(ret.message, 0, 100);
    time_t curr_time = reset_data(enclave_state);
    if (curr_time == 0) {
        sprintf(ret.message, "reset_data failed");
        printf("[sdt] %s\n", ret.message);
        ret.error = 1;
        return ret;
    }

    int user_idx = -1;
    for(int i = 0; i < enclave_state->num_users; i++) {
        if(strncmp(&CI->user_pubkey, &enclave_state->publickeys.user_pubkeys[i], sizeof(secp256k1_pubkey)) == 0) {
          user_idx = i;
          break;
        }
    }

    if (user_idx == -1) {
         sprintf(ret.message, "[sdt] invalid user public key");
         printf("%s\n", ret.message);
         ret.error = 2;
         return ret;
    }

    if(DEBUGPRINT) printf("[sdt startRetrieve uidx %d\n", user_idx);


    if (enclave_state->appdata.retrieve_count >= MAX_RETRIEVE) {
        sprintf(ret.message, "retrieve_count limit reached %d > %d", enclave_state->appdata.retrieve_count, MAX_RETRIEVE);
        printf("[sdt] %s\n", ret.message);
        ret.error = 3;
        return ret;
    }
    struct userInfo ui = enclave_state->appdata.user_info[user_idx];
    if (ui.started_retrieve) {
        sprintf(ret.message, "retrieval already started");
        printf("[sdt] %s\n", ret.message);
        ret.error = 4;
        return ret;
    }
    enclave_state->appdata.user_info[user_idx].retrieve_count++; // todo delete?

    enclave_state->appdata.user_info[user_idx].retrieve_time = curr_time + WAIT_TIME;
    enclave_state->appdata.user_info[user_idx].started_retrieve = true;
    memcpy(enclave_state->appdata.user_info[user_idx].recover_key_hash, CI->recover_key_hash, HASH_SIZE);

    enclave_state->appdata.retrieve_count++;
    sprintf(ret.message, "success startRetrieve");
    if(DEBUGPRINT) printf("[sdt] %s\n", ret.message);
    return ret;
}

/* COMMAND2 Kernel Definition */
struct cResponse completeRetrieve(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    if(DEBUGPRINT) printf("[sdt] completeRetrieve\n");
    struct cResponse ret;
    ret.error = 0;
    memset(ret.output_data, 0, DATA_SIZE);
    memset(ret.message, 0, 100);
    time_t curr_time = reset_data(enclave_state);
    if (curr_time == 0) {
        sprintf(ret.message, "reset_data failed");
        printf("[sdt] %s\n", ret.message);
        ret.error = 1;
        return ret;
    }

    if(DEBUGPRINT) {
        printf("[sdt] new user_pubkey ");
        print_hexstring(CI->user_pubkey, 64);
    }

    int user_idx = -1;
    for(int i = 0; i < enclave_state->num_users; i++) {
        if(strncmp(CI->user_pubkey, enclave_state->publickeys.user_pubkeys[i], 64) == 0) {
          user_idx = i;
          break;
        }
    }
    if (user_idx == -1) {
         sprintf(ret.message, "invalid user public key");
         printf("[sdt] %s\n", ret.message);
         ret.error = 2;
         return ret;
    }
    if(DEBUGPRINT) printf("[sdt] completeRetrieve uidx %d\n", user_idx);
    struct userInfo ui = enclave_state->appdata.user_info[user_idx];
    if (!ui.started_retrieve) {
        sprintf(ret.message, "retrieval not started");
        printf("[sdt] %s\n", ret.message);
        ret.error = 3;
        return ret;
    }

    if (curr_time < ui.retrieve_time) {
        sprintf(ret.message, "retrieval wait period not over %lu < %lu", curr_time, ui.retrieve_time);
        printf("[sdt] %s\n", ret.message);
        ret.error = 4;
        return ret;
    }


    char key_hash[HASH_SIZE];
    sha256(CI->recover_key, KEY_SIZE, key_hash);

    if(strncmp(enclave_state->appdata.user_info[user_idx].recover_key_hash, key_hash, HASH_SIZE) != 0) {
        sprintf(ret.message, "recover key does not match recover_key_hash");
        printf("[sdt] %s", ret.message);
        if (DEBUGPRINT) {
            printf(" expected: ");
            print_hexstring_n(enclave_state->appdata.user_info[user_idx].recover_key_hash, HASH_SIZE);
            printf(" got: ");
            print_hexstring_n(key_hash, HASH_SIZE);
        }
        printf("\n");
        ret.error = 5;
        return ret;
    }


    memcpy(&enclave_state->publickeys.user_pubkeys[user_idx], &CI->recover_key, KEY_SIZE);
    enclave_state->appdata.user_info[user_idx].started_retrieve = false;
    enclave_state->appdata.user_info[user_idx].retrieve_time = 0;

    sprintf(ret.message, "success completeRetrieve");
    if(DEBUGPRINT) printf("[sdt] %s\n", ret.message);
    return ret;
}

/* COMMAND3 Kernel Definition */
struct cResponse cancelRetrieve(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    if(DEBUGPRINT) printf("[sdt] cancelRetrieve uidx %d\n", uidx);

    struct cResponse ret;
    memset(ret.output_data, 0, DATA_SIZE);
    memset(ret.message, 0, 100);
    ret.error = 0;
    time_t curr_time = reset_data(enclave_state);
    if (curr_time == 0) {
        sprintf(ret.message, "reset_data failed");
        printf("[sdt] %s\n", ret.message);
        ret.error = 1;
        return ret;
    }

    if (!enclave_state->appdata.user_info[uidx].started_retrieve) {
        sprintf(ret.message, "retrieval not started");
        printf("[sdt] %s\n", ret.message);
        ret.error = 2;
        return ret;
    }
    ret.error = 0;
    enclave_state->appdata.user_info[uidx].started_retrieve = false;
    enclave_state->appdata.user_info[uidx].retrieve_time = 0;
    sprintf(ret.message, "success cancelRetrieve");
    if(DEBUGPRINT) printf("[sdt] %s\n", ret.message);
    return ret;
}

#ifdef MERKLE_TREE
size_t calc_user_leaf_size(struct ES *enclave_state)
{
    return sizeof(struct userLeaf);
}

size_t get_user_leaf(struct ES *enclave_state, uint8_t ** out)
{
    size_t block_size = sizeof(struct userLeaf);
    for (int i=0; i< enclave_state->num_users; i++) {
        out[i] = (uint8_t *) malloc(block_size);
        struct userInfo info = enclave_state->appdata.user_info[i];
        struct userLeaf leaf = {info.retrieve_count, info.retrieve_time, info.started_retrieve, i};
        memcpy(out[i], &leaf, block_size);
    }
    return block_size;
}

void free_user_leaf(struct ES *enclave_state, uint8_t **data) {
    if (data != NULL){
        for(int i = 0; i < enclave_state->num_users; i++){
            if (data[i] != NULL){
                free(data[i]);
                data[i] = NULL;
            }
        }
    }
}

#endif



/* Initializes the Function Pointers to Function Names Above */
int initFP(struct cResponse (*functions[NUM_COMMANDS+NUM_ADMIN_COMMANDS])(struct ES*, struct cInputs*, uint32_t)){
    (functions[ADD_DATA]) = &addPersonalData;
    (functions[CANCEL_RET]) = &cancelRetrieve;
    (functions[GET_DATA]) = &getPersonalData;

    (functions[START_RET]) = &startRetrieve; //admin
    (functions[COMPLETE_RET]) = &completeRetrieve; //admin

    //printf("Initialized Application Kernels\n");
    return 0;
}


/* Initializes the Application Data as per expectation */
int initES(struct ES* enclave_state, struct dAppData *dAD, uint64_t num_users, bool dry_run)
{
    size_t user_info_size = sizeof(struct userInfo) * num_users;
    enclave_state->appdata.user_info = (struct userInfo *) malloc(user_info_size);
    for (int i = 0; i < num_users; i++) {
        enclave_state->appdata.user_info[i].started_retrieve = false;
        enclave_state->appdata.user_info[i].retrieve_time = 0;
        enclave_state->appdata.user_info[i].retrieve_count = 0;
        memset(enclave_state->appdata.user_info[i].secret_data, 0, DATA_SIZE);
    }
    enclave_state->appdata.retrieve_count = 0;
    time_t curr_time;
    if (!dry_run) {
        int res = get_timestamp(&curr_time);
        if (res != 0) {
            return res;
        }
    }
    enclave_state->appdata.last_reset_time = curr_time;
    /* Initialize metadata regarding dynamic data-structures for sealing purposes */

    // Number of dynamic data structures
    dAD->num_dDS = 1;

    // For each dDS, assign the pointer and the size of the DS
    struct dynamicDS *dDS = (struct dynamicDS *)malloc(dAD->num_dDS * sizeof(struct dynamicDS));
    if(dDS == NULL) return -1;
    dDS[0].buffer = enclave_state->appdata.user_info;
    dDS[0].buffer_size = user_info_size;
    dAD->dDS = dDS;
    return 0;
}

int initAD(struct ES* enclave_state, struct dAppData *dAD)
{
   enclave_state->appdata.user_info = dAD->dDS[0].buffer;
//    enclave_state->appdata.retrieve_list = dAD->dDS[1]->buffer;
    return 0;
}

void formatResponse(struct cResponse *ret, int error, char * message) {
    ret->error = error;
    memset(ret->output_data, 0, DATA_SIZE);
    memcpy(ret->message, message, 100);
}

/* Debug Print Statement to Visualize clientCommands */
void print_clientCommand(struct clientCommand *CC, uint32_t uidx){
    printf("[sdt] Readable eCMD: {[uidx]: %u [CT]:%u ", uidx, CC->eCMD.CT);
  if (CC->eCMD.CT == ADD_DATA){
    printf("ADD_DATA | input_data:");
    print_hexstring_trunc_n(CC->eCMD.CI.input_data, DATA_SIZE);
  }
  if (CC->eCMD.CT == CANCEL_RET) {
    printf("CANCEL_RET");
  }
  if (CC->eCMD.CT == GET_DATA){
    printf("GET_DATA");
  }
  if (CC->eCMD.CT == START_RET){
    printf("START_RET | recover_key_hash:");
    print_hexstring_trunc_n(CC->eCMD.CI.recover_key_hash, HASH_SIZE);
  }
  if (CC->eCMD.CT == COMPLETE_RET){
    printf("START_RET | recover_key:");
    print_hexstring_trunc_n(CC->eCMD.CI.recover_key, KEY_SIZE);
  }
  printf(" [SN]:%lu}\n", CC->seqNo);
}

