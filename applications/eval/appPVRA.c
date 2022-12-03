#include "enclave_state.h"
#include "appPVRA.h"
#include "merkletree.h"  // todo remove no MERKLE

/* COMMAND0 Kernel Definition */
struct cResponse userCMD0(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    if(DEBUGPRINT) printf("[template] userCMD0 %d\n", uidx);
    struct cResponse ret;
    memset(ret.message, 0, 100);
    ret.error = 0;
    sprintf(ret.message, "success USER_CMD0 %u", uidx);
    return ret;
}

#ifdef MERKLE_TREE  // todo remove no MERKLE
size_t get_user_leaf(struct ES *enclave_state, char ** out) {
    if(DEBUGPRINT) printf("[template] get_user_leaf\n");
    size_t block_size = sizeof(struct userLeaf);
    for (int i=0; i< NUM_USERS; i++) {
        out[i] = (char *) malloc(block_size);
        struct userInfo info = enclave_state->appdata.user_info[i];
        memcpy_big_uint32(out[i], info.uidx);
    }
    return block_size;
}
#endif



/* Initializes the Function Pointers to Function Names Above */
int initFP(struct cResponse (*functions[NUM_COMMANDS+NUM_ADMIN_COMMANDS])(struct ES*, struct cInputs*)){
    (functions[0]) = &userCMD0;
//    (functions[1]) = &adminCMD1; //admin

//  if(DEBUGPRINT) printf("Initialized Application Kernels\n");
    return 0;
}


/* Initializes the Application Data as per expectation */
int initES(struct ES* enclave_state, struct dAppData *dAD)
{
    for (int i = 0; i < NUM_USERS; i++) {
        enclave_state->appdata.user_info[i].uidx = i;
    }

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
//
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

