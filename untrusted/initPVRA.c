#include <stdlib.h>

#include <enclave_u.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>

#include "app.h"

bool initPVRA(uint64_t num_users) {

  printf("[hiPVRA] Invoking ecall_initPVRA\n");

  sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;
  sgx_report_t report;
  sgx_spid_t spid;
  sgx_target_info_t target_info;
  sgx_epid_group_id_t epid_gid;
  sgx_status_t status;

  status = sgx_init_quote(&target_info, &epid_gid);
  memset(&report, 0, sizeof(report));

  clock_t t;
  t = clock();

  tsc_idx = 0;

  sgx_lasterr = ecall_initPVRA(
      enclave_id, &ecall_retval, 
      &target_info, num_users,
      (char *)pubkeys_buffer, pubkeys_buffer_size,
      &report,
      (uint8_t *)sealed_state_buffer, sealed_state_buffer_size,
      enclave_pubkey_buffer,
      enclave_pubkey_signature_buffer,
      user_addr_signature_buffer);

  t = clock() - t;
  double time_taken = ((double)t)/CLOCKS_PER_SEC; // calculate the elapsed time
  printf("[hiPVRA] ecall_initPVRA took %f seconds\n", time_taken);

  for(int i = 0; i < tsc_idx; i++)
    printf("%lu\n", tsc_dump[i]);

  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
    fprintf(stderr, "[GatewayApp][initPVRA]: ERROR: ecall_initPVRA returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }


  // calculate quote size
  sgx_quote_t *quote;
  uint32_t quote_size = 0;

  status = sgx_calc_quote_size(NULL, 0, &quote_size);
  if (status != SGX_SUCCESS) {
    fprintf(stderr, "SGX error while getting quote size: %08x\n", status);
    return 1;
  }

  quote = (sgx_quote_t *)malloc(quote_size);
  if (quote == NULL) {
    fprintf(stderr, "out of memory\n");
    return 1;
  }
  memset(quote, 0, quote_size);

  // get quote
  sgx_quote_sign_type_t unlinkable = SGX_UNLINKABLE_SIGNATURE;

  if ( getenv( "SGX_SPID" ) != NULL && strnlen(getenv( "SGX_SPID" ), 32) == 32){
    from_hexstring((unsigned char *)&spid, (unsigned char *)getenv("SGX_SPID"), 16);
      printf("SGX_SPID environment variable set to %s\n", getenv( "SGX_SPID" ));
  } else{
    if (getenv( "SGX_MODE" ) != NULL && strcmp(getenv( "SGX_MODE" ), "HW\0") != 0){
      char * dummy_spid = "00000000000000000000000000000000\0";
      printf("SGX_SPID environment variable not set defaulting to %s\n", dummy_spid);
      from_hexstring((unsigned char *)&spid, (unsigned char *)dummy_spid, 16);
    } else {
      printf("SGX_SPID environment variable not set\n");
      return -1;
    }
  }

  status = sgx_get_quote(&report, unlinkable, &spid, NULL, NULL, 0, NULL, quote,
                         quote_size);


  if (status != SGX_SUCCESS) {
    printf("[GatewayApp]: sgx_get_quote: error %s\n", decode_sgx_status(status));
    return 1;
  }

  quote_buffer_size = quote_size;
  quote_buffer = calloc(quote_buffer_size, sizeof(char));
  // copy quote and quote_size into globals
  memcpy(quote_buffer, quote, quote_size);
  memcpy(&quote_buffer_size, &quote_size, sizeof(quote_size));

  printf("[hiPVRA] MRENCLAVE: \t");
  print_hexstring(stdout, &quote->report_body.mr_enclave,
                  sizeof(sgx_measurement_t));
  printf("\n[hiPVRA] MRSIGNER: \t");
  print_hexstring(stdout, &quote->report_body.mr_signer,
                  sizeof(sgx_measurement_t));
  printf("\n[hiPVRA] Report Data: \t");
  print_hexstring(stdout, &quote->report_body.report_data,
                  sizeof(sgx_report_data_t));
  printf("\n");

  char *b64quote = NULL;
  b64quote = base64_encode((char *)quote, quote_size);
  if (b64quote == NULL) {
    printf("Could not base64 encode quote\n");
    return 1;
  }
/*
  printf("Quote, ready to be sent to IAS (POST /attestation/v4/report):\n");
  printf("{\n");
  printf("\t\"isvEnclaveQuote\":\"%s\"", b64quote);
  // if (OPT_ISSET(flags, OPT_NONCE)) {
  //    printf(",\n\t\"nonce\":\"");
  //    print_hexstring(stdout, &config->nonce, 16);
  //    printf("\"");
  //}

  printf("\n}\n\n");
  printf("See "
         "https://api.trustedservices.intel.com/documents/"
         "sgx-attestation-api-spec.pdf\n"); */

  return (sgx_lasterr == SGX_SUCCESS);


}

