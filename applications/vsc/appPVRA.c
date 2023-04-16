#include "enclave_state.h"
#include "appPVRA.h"


/* COMMAND0 Kernel Definition */
struct cResponse statusUpdate(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    if(DEBUGPRINT) printf("[vsc] statusUpdate uidx %d\n", uidx);
    struct cResponse ret;
    ret.error = 0;
    ret.access = false;
    memset(ret.message, 0, 100);

    uint32_t test_idx = enclave_state->appdata.user_tests[uidx].num_tests % MAX_TEST;

    enclave_state->appdata.user_tests[uidx].test_history[test_idx] = CI->test_result;
    enclave_state->appdata.user_tests[uidx].num_tests++;
    if(DEBUGPRINT) printf("[vsc] test_result %d num_tests %u\n", enclave_state->appdata.user_tests[uidx].test_history[test_idx],
     enclave_state->appdata.user_tests[uidx].num_tests);

    sprintf(ret.message, "success statusUpdate");
    if(DEBUGPRINT) printf("[vsc] %s\n", ret.message);

    return ret;
}


/* COMMAND1 Kernel Definition */
struct cResponse statusQuery(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    if(DEBUGPRINT) printf("[vsc] statusQuery uidx %d\n", uidx);
    struct cResponse ret;
    ret.error = 0;
    ret.access = false;
    memset(ret.message, 0, 100);

    enclave_state->appdata.user_tests[uidx].query_counter++;
    if(DEBUGPRINT) printf("[vsc] query_counter %u\n", enclave_state->appdata.user_tests[uidx].query_counter);

    if(enclave_state->appdata.user_tests[uidx].num_tests < MIN_NEG) {
        sprintf(ret.message, "insufficient testing");
        printf("[vsc] %s\n", ret.message);
        ret.error = 1;
        return ret;
    }
    bool all_false = true;
    uint64_t next_test_idx;
    for (uint64_t i = 0; i < MIN_NEG; i++) {
        next_test_idx = (enclave_state->appdata.user_tests[uidx].num_tests-1-i) % MAX_TEST;
        all_false = all_false && !enclave_state->appdata.user_tests[uidx].test_history[next_test_idx];
    }
    
    if (all_false) {
        ret.access = true;
        sprintf(ret.message, "ACCESS GRANTED");
    } else {
        ret.access = false;
        sprintf(ret.message, "ACCESS DENIED");
    }

    if(DEBUGPRINT) printf("[vsc] statusQuery %s access %d\n", ret.message, ret.access);
    return ret;
}



/* Initializes the Function Pointers to Function Names Above */
int initFP(struct cResponse (*functions[NUM_COMMANDS])(struct ES*, struct cInputs*)) 
{
    (functions[0]) = &statusUpdate;
    (functions[1]) = &statusQuery;
    //printf("Initialized Application Kernels\n");
    return 0;
}


/* Initializes the Application Data in initPVRA*/
int initES(struct ES* enclave_state, struct dAppData *dAD, uint64_t num_users, bool dry_run)
{
    size_t user_data_size = num_users*sizeof(struct userTests);
    enclave_state->appdata.user_tests = (struct userTests *) malloc(user_data_size);
    if(enclave_state->appdata.user_tests == NULL) return -1;
    for (uint64_t i = 0; i< num_users; i++) {
        enclave_state->appdata.user_tests[i].num_tests = 0;
        enclave_state->appdata.user_tests[i].query_counter = 0;
        for (uint64_t j = 0; j < MAX_TEST; j++) {
            enclave_state->appdata.user_tests[i].test_history[j] = true;
        }        
    }
    /* Initialize metadata regarding dynamic data-structures for sealing purposes */

    // Number of dynamic data structures
    dAD->num_dDS = 1;

    struct dynamicDS *dDS = (struct dynamicDS **)calloc(dAD->num_dDS, sizeof(struct dynamicDS));
    if(dDS == NULL) return -1;
    dDS[0].buffer = enclave_state->appdata.user_tests;
    dDS[0].buffer_size = user_data_size;
    dAD->dDS = dDS;
    return 0;
}


/* Initializes the Application Data dynamic structure pointers in commandPVRA */
int initAD(struct ES* enclave_state, struct dAppData *dAD)
{
    enclave_state->appdata.user_tests = dAD->dDS[0].buffer;
    return 0;
}

void formatResponse(struct cResponse *ret, int error, char * message) {
    ret->error = error;
    ret->access = false;
    memcpy(ret->message, message, 100);
}

/* Debug Print Statement to Visualize clientCommands */
void print_clientCommand(struct clientCommand *CC, uint32_t uidx){
  printf("[vsc] Readable eCMD: {[CT]:%d [CI]:%d,%d [SN]:%lu} ", CC->eCMD.CT, uidx, CC->eCMD.CI.test_result, CC->seqNo);
}

