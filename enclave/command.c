#include "enclavestate.h"
#include "command.h"



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




int initFP(struct cResponse (*functions[NUM_COMMANDS])(struct ES*, struct cInputs*)) 
{
    (functions[0]) = &statusUpdate;
    (functions[1]) = &statusQuery;
    //printf("Initialized Application Kernels\n");
    return 0;
}


int initES(struct ES* enclave_state)
{
    for(int i = 0; i < NUM_USERS; i++) {
        enclave_state->appdata.query_counter[i] = 0; 
        enclave_state->appdata.num_tests[i] = 0;
        for(int j = 0; j < NUM_TESTS; j++) {
            enclave_state->appdata.test_history[i*NUM_TESTS + j] = -1;
        }
    }
    //printf("Initialized Application State\n");
    return 0;
}



char *format_cResponse(struct cResponse cRet) {
    char cRstring[2] = "0";
    return cRstring;
}

void print_clientCommand(struct clientCommand *CC){
  printf("[apPVRA] Readable eCMD: {[CT]:%d [CI]:%d,%d [SN]:%d [ID]:%d} ", CC->CT.tid, CC->CI.uid, CC->CI.test_result, CC->seqNo, CC->cid);
}

