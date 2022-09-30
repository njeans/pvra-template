/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdlib.h>

#include <enclave_u.h> /* For sgx_enclave_id_t */

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>

#include "app.h"

bool initPVRA() {

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
      enclave_id, &ecall_retval, &report, &target_info, (char *)sealed_state_buffer,
      sealed_state_buffer_size, (char *)signature_buffer, signature_buffer_size, (char *)pub_enckey_buffer, pub_enckey_buffer_size);

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

  //printf("[GatewayApp]: Call sgx_calc_quote_size() ...\n");
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

  //printf("[GatewayApp]: SPID: %s\n", getenv("SGX_SPID"));
  from_hexstring((unsigned char *)&spid, (unsigned char *)getenv("SGX_SPID"),
                 16); 
  //printf("[GatewayApp]: Call sgx_get_quote() ...\n");
  status = sgx_get_quote(&report, unlinkable, &spid, NULL, NULL, 0, NULL, quote,
                         quote_size);
  //fprintf(stdout, "[GatewayApp]: status of sgx_get_quote(): %08x\n", status);
  printf("[hiPVRA] status of sgx_get_quote(): %s\n",
         status == SGX_SUCCESS ? "success" : "error");
  if (status != SGX_SUCCESS) {
    fprintf(stderr, "[GatewayApp]: sgx_get_quote: %08x\n", status);
    return 1;
  }

  quote_buffer_size = quote_size;
  quote_buffer = calloc(quote_buffer_size, sizeof(char));
  // copy quote and quote_size into globals
  memcpy(quote_buffer, quote, quote_size);
  memcpy(&quote_buffer_size, &quote_size, sizeof(quote_size));

  printf("\n[hiPVRA] MRENCLAVE: \t");
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

