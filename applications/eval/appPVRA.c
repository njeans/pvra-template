#include "enclave_state.h"
#include "appPVRA.h"

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
    for (int i = 0; i < enclave_state->num_users; i++) {
        enclave_state->appdata.user_info[i].uidx = i;
    }
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

