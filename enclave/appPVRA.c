#include "enclavestate.h"
#include "appPVRA.h"


/* COMMAND0 Kernel Definition */
struct cResponse statusUpdate(struct ES *enclave_state, struct cInputs *CI)
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

    if(enclave_state->appdata.num_tests[CI->uid] == NUM_TESTS) {
        char *m = "[apPVRA] STATUS_UPDATE ERROR full test_history";
        printf("%s\n", m);
        memcpy(ret.message, m, strlen(m)+1);
        ret.error = 2;
        return ret;
    }

    if((CI->test_result != 0) && (CI->test_result != 1))
    {
        char *m = "[apPVRA] STATUS_UPDATE ERROR invalid test_result";
        printf("%s [%d]\n", m, CI->test_result);
        memcpy(ret.message, m, strlen(m)+1);
        ret.error = 3;
        return ret;
    }

    ret.error = 0;
    char *m = "[apPVRA] STATUS_UPDATE SAVED test_result";
    //printf("%s %d %d %d %d\n", m, enclave_state->appdata.test_history[CI->uid*NUM_TESTS + enclave_state->appdata.num_tests[CI->uid]], enclave_state->appdata.num_tests[CI->uid], enclave_state->appdata.query_counter[CI->uid], CI->test_result);
    memcpy(ret.message, m, strlen(m)+1);
    enclave_state->appdata.test_history[(CI->uid)*NUM_TESTS + (enclave_state->appdata.num_tests[CI->uid])] = CI->test_result;
    enclave_state->appdata.num_tests[CI->uid]++;
    enclave_state->appdata.query_counter[CI->uid]++;

    //printf("%s %d %d %d\n", m, enclave_state->appdata.test_history[CI->uid*NUM_TESTS + enclave_state->appdata.num_tests[CI->uid]-1], enclave_state->appdata.num_tests[CI->uid], enclave_state->appdata.query_counter[CI->uid]);

    return ret;
}


/* COMMAND1 Kernel Definition */
struct cResponse statusQuery(struct ES *enclave_state, struct cInputs *CI)
{
    struct cResponse ret;

    enclave_state->appdata.query_counter[CI->uid]++;

    if(CI->uid > NUM_USERS-1) {
        char *m = "[apPVRA] STATUS_QUERY ERROR invalid userID";
        printf("%s\n", m);
        memcpy(ret.message, m, strlen(m)+1);
        ret.error = 1;
        return ret;
    }

    if(enclave_state->appdata.num_tests[CI->uid] < 2) {
        char *m = "[apPVRA] STATUS_QUERY ERROR insufficient testing";
        printf("%s\n", m);
        memcpy(ret.message, m, strlen(m)+1);
        ret.error = 2;
        return ret;
    }

    ret.error = 0;
    if ( (enclave_state->appdata.test_history[CI->uid*NUM_TESTS + enclave_state->appdata.num_tests[CI->uid]-1] == 0) &&
            (enclave_state->appdata.test_history[CI->uid*NUM_TESTS + enclave_state->appdata.num_tests[CI->uid]-2] == 0) ) {
        ret.access = true;
        char *m = "[apPVRA] STATUS_QUERY ACCESS GRANTED";
        printf("%s\n", m);
        memcpy(ret.message, m, strlen(m)+1);
    }
    else {
        ret.access = false;
        char *m = "[apPVRA] STATUS_QUERY ACCESS DENIED";
        printf("%s LAST TEST RESULTS:[%d,%d]\n", m, enclave_state->appdata.test_history[CI->uid*NUM_TESTS + enclave_state->appdata.num_tests[CI->uid]-2], enclave_state->appdata.test_history[CI->uid*NUM_TESTS + enclave_state->appdata.num_tests[CI->uid]-1]);
        memcpy(ret.message, m, strlen(m)+1);
    }

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


/* Initializes the Application Data as per expectation */
int initES(struct ES* enclave_state, struct dAppData *dAD)
{
    char *test_history = calloc(INIT_NUM_USERS*INIT_NUM_TESTS, sizeof(char));
    if(test_history == NULL) return -1;

    int *num_tests = calloc(INIT_NUM_USERS, sizeof(int));
    if(num_tests == NULL) 
        return -1;

    int *query_counter = calloc(INIT_NUM_USERS, sizeof(int));
    if(query_counter == NULL) 
        return -1;

    enclave_state->appdata.query_counter = query_counter;
    enclave_state->appdata.num_tests = num_tests;
    enclave_state->appdata.test_history = test_history;

    for(int i = 0; i < NUM_USERS; i++) {
        enclave_state->appdata.query_counter[i] = 6; 
        enclave_state->appdata.num_tests[i] = 7;
        for(int j = 0; j < NUM_TESTS; j++) {
            enclave_state->appdata.test_history[i*NUM_TESTS + j] = 8;
        }
    }


    /* Initialize metadata regarding dynamic data-structures for sealing purposes */

    // Number of dynamic data structures
    dAD->num_dDS = 3;

    // For each dDS, assign the pointer and the size of the DS
    struct dynamicDS *tDS = (struct dynamicDS *)calloc(1, sizeof(struct dynamicDS));
    if(tDS == NULL) return -1;
    tDS->buffer = test_history;
    tDS->buffer_size = INIT_NUM_USERS*INIT_NUM_TESTS*sizeof(char);

    struct dynamicDS *nDS = (struct dynamicDS *)calloc(1, sizeof(struct dynamicDS));
    if(nDS == NULL) return -1;
    nDS->buffer = num_tests;
    nDS->buffer_size = INIT_NUM_USERS*sizeof(int);

    struct dynamicDS *qDS = (struct dynamicDS *)calloc(1, sizeof(struct dynamicDS));
    if(qDS == NULL) return -1;
    qDS->buffer = test_history;
    qDS->buffer_size = INIT_NUM_USERS*sizeof(int);

    struct dynamicDS **dDS = (struct dynamicDS **)calloc(3, sizeof(struct dynamicDS *));
    if(dDS == NULL) return -1;
    dDS[0] = tDS;
    dDS[1] = nDS;
    dDS[2] = qDS;
    dAD->dDS = dDS;
    return 0;
}

int initAD(struct ES* enclave_state, struct dAppData *dAD)
{
    enclave_state->appdata.test_history = dAD->dDS[0]->buffer;
    enclave_state->appdata.num_tests = dAD->dDS[1]->buffer;
    enclave_state->appdata.query_counter = dAD->dDS[2]->buffer;
    return 0;
}



/* Debug Print Statement to Visualize clientCommands */
void print_clientCommand(struct clientCommand *CC){
  printf("[apPVRA] Readable eCMD: {[CT]:%d [CI]:%d,%d [SN]:%d [ID]:%d} ", CC->CT.tid, CC->CI.uid, CC->CI.test_result, CC->seqNo, CC->cid);
}

