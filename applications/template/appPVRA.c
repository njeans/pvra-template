#include "enclave_state.h"
#include "appPVRA.h"
#include "merkletree.h"  // todo remove no MERKLE

/* COMMAND0 Kernel Definition */
struct cResponse userCMD0(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    if(DEBUGPRINT) printf("[template] userCMD0 %u\n", uidx);
    struct cResponse ret;
    memset(ret.message, 0, 100);
    ret.error = 0;
    sprintf(ret.message, "success USER_CMD0 %u", uidx);
    return ret;
}

/* COMMAND1 Kernel Definition */
struct cResponse adminCMD1(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    if(DEBUGPRINT) printf("[template] adminCMD1 admin_uidx: %u\n", CI->admin_uidx);
    struct cResponse ret;
    ret.error = 0;
    memset(ret.message, 0, 100);
    sprintf(ret.message, "success ADMIN_CMD1 %u", CI->admin_uidx);
    return ret;
}

#ifdef MERKLE_TREE  // todo remove no MERKLE
size_t get_user_leaf(struct ES *enclave_state, char ** out) {
    if(DEBUGPRINT) printf("[template] get_user_leaf\n");
    size_t block_size = sizeof(struct userLeaf);
    for (int i=0; i< enclave_state->num_users; i++) {
        out[i] = (char *) malloc(block_size);
        struct userInfo info = enclave_state->appdata.user_info[i];
        struct userLeaf leaf= {info.uidx};
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
int initFP(struct cResponse (*functions[NUM_COMMANDS+NUM_ADMIN_COMMANDS])(struct ES*, struct cInputs*)){
    (functions[0]) = &userCMD0;
    (functions[1]) = &adminCMD1; //admin

//  if(DEBUGPRINT) printf("Initialized Application Kernels\n");
    return 0;
}


/* Initializes the Application Data as per expectation */
int initES(struct ES* enclave_state, struct dAppData *dAD, uint64_t num_users)
{
    size_t user_data_size = num_users*sizeof(struct userInfo);
    enclave_state->appdata.user_info= (struct cInputs *) malloc(user_data_size);
    if(enclave_state->appdata.user_info == NULL) return -1;

    for (uint64_t i = 0; i< num_users; i++) {
        enclave_state->appdata.user_info[i].uidx = i; 
    }

    /* Initialize metadata regarding dynamic data-structures for sealing purposes */

    // Number of dynamic data structures
    dAD->num_dDS = 1;

    struct dynamicDS **dDS = (struct dynamicDS **)calloc(dAD->num_dDS, sizeof(struct dynamicDS *));
    if(dDS == NULL) return -1;
    dDS[0]->buffer = enclave_state->appdata.user_info;
    dDS[0]->buffer_size = user_data_size;

    return 0;
}

int initAD(struct ES* enclave_state, struct dAppData *dAD)
{
   enclave_state->appdata.user_info = dAD->dDS[0]->buffer;
    return 0;
}

void formatResponse(struct cResponse *ret, int error, char * message) {
    ret->error = error;
    memcpy(ret->message, message, 100);
}

/* Debug Print Statement to Visualize clientCommands */
void print_clientCommand(struct clientCommand *CC, uint32_t uidx){
  printf("[template] Readable eCMD: {[CT]:%d [CI]:%d [SN]:%lu}", CC->eCMD.CT, uidx, CC->seqNo);
}

