#include "enclavestate.h"
#include "appPVRA.h"


/* COMMAND0 Kernel Definition */
struct cResponse statusUpdate(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    printf("[apPVRA] statusUpdate %d\n", uidx);
    struct cResponse ret;
    ret.error = 0;
    ret.access = false;
    memset(ret.message, 0, 100);
    if(enclave_state->appdata.num_tests[uidx] == NUM_TESTS) {
        sprintf(ret.message, "error full test_history");
        printf("[apPVRA] %s\n", ret.message);
        ret.error = 1;
        return ret;
    }

    enclave_state->appdata.test_history[(uidx)*NUM_TESTS + (enclave_state->appdata.num_tests[uidx])] = CI->test_result;
    enclave_state->appdata.num_tests[uidx]++;
    printf("[apPVRA] num_tests %u\n", enclave_state->appdata.num_tests[uidx]);
    enclave_state->appdata.query_counter[uidx]++;
    printf("[apPVRA] query_counter %u\n", enclave_state->appdata.query_counter[uidx]);

    sprintf(ret.message, "success statusUpdate");
    printf("[apPVRA] %s\n", ret.message);

    return ret;
}


/* COMMAND1 Kernel Definition */
struct cResponse statusQuery(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    printf("[apPVRA] statusQuery %d\n", uidx);
    struct cResponse ret;
    ret.error = 0;
    ret.access = false;
    memset(ret.message, 0, 100);

    printf("[apPVRA] num_tests %u\n", enclave_state->appdata.num_tests[uidx]);

    enclave_state->appdata.query_counter[uidx]++;
    printf("[apPVRA] query_counter %u\n", enclave_state->appdata.query_counter[uidx]);

    if(enclave_state->appdata.num_tests[uidx] < 2) {
        sprintf(ret.message, "insufficient testing");
        printf("[apPVRA] %s\n", ret.message);
        ret.error = 1;
        return ret;
    }

    if ( (enclave_state->appdata.test_history[uidx*NUM_TESTS + enclave_state->appdata.num_tests[uidx]-1] == 0) &&
            (enclave_state->appdata.test_history[uidx*NUM_TESTS + enclave_state->appdata.num_tests[uidx]-2] == 0) ) {
        ret.access = true;
        sprintf(ret.message, "ACCESS GRANTED");
    }
    else {
        ret.access = false;
        sprintf(ret.message, "ACCESS DENIED");
    }

    printf("[apPVRA] statusQuery %s access %d %d %d\n", ret.message, ret.access, true, false);
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
int initES(struct ES* enclave_state, struct dAppData *dAD)
{
    /* Allocate buffers for dynamic structures */
    char *test_history = calloc(INIT_NUM_USERS*INIT_NUM_TESTS, sizeof(char));
    if(test_history == NULL) return -1;

    int *num_tests = calloc(INIT_NUM_USERS, sizeof(int));
    if(num_tests == NULL) return -1;

    int *query_counter = calloc(INIT_NUM_USERS, sizeof(int));
    if(query_counter == NULL) return -1;

    enclave_state->appdata.query_counter = query_counter;
    enclave_state->appdata.num_tests = num_tests;
    enclave_state->appdata.test_history = test_history;

    /* Set Initial Values */
    for(int i = 0; i < NUM_USERS; i++) {
        enclave_state->appdata.query_counter[i] = 0;
        enclave_state->appdata.num_tests[i] = 0;
        for(int j = 0; j < NUM_TESTS; j++) {
            enclave_state->appdata.test_history[i*NUM_TESTS + j] = true;
        }
    }


    /* Initialize metadata regarding dynamic data-structures for sealing purposes */
    /* struct dAppData stores this metadata */

    // Number of dynamic data structures
    dAD->num_dDS = 3;

    // For each dynamic data structure:
    // 1. allocate a struct dynamicDS (basically stores a buffer_ptr + buffer_size) 
    // 2. assign the dynamicDS.buffer to allocated buffer ptr
    // 3. assign the dynamicDS.buffer_size to the size in BYTES of the buffer

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


    // Allocate an array of struct dynamicDS * pointers
    struct dynamicDS **dDS = (struct dynamicDS **)calloc(3, sizeof(struct dynamicDS *));
    if(dDS == NULL) return -1;

    // Assign each struct dynamicDS to a array entry
    dDS[0] = tDS;
    dDS[1] = nDS;
    dDS[2] = qDS;
    dAD->dDS = dDS;

    return 0;
}


/* Initializes the Application Data dynamic structure pointers in commandPVRA */
int initAD(struct ES* enclave_state, struct dAppData *dAD)
{
    enclave_state->appdata.test_history = dAD->dDS[0]->buffer;
    enclave_state->appdata.num_tests = dAD->dDS[1]->buffer;
    enclave_state->appdata.query_counter = dAD->dDS[2]->buffer;
    return 0;
}



/* Debug Print Statement to Visualize clientCommands */
void print_clientCommand(struct clientCommand *CC, uint32_t uidx){
  printf("[apPVRA] Readable eCMD: {[CT]:%d [CI]:%d,%d [SN]:%d} ", CC->eCMD.CT, uidx, CC->eCMD.CI.test_result, CC->eCMD.seqNo);
}

