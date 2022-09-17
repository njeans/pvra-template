#include <stdlib.h>

#include <enclave_u.h> /* For sgx_enclave_id_t */

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <time.h>

#include "app.h"

bool enclave_generate_key_vsc() {
  sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

  printf("[GatewayApp]: Calling enclave to generate VSC key\n");

  /*
   * Invoke ECALL, 'ecall_key_gen_vsc()', to generate a key
   */
   
   clock_t t;
   t = clock();


   
   
  sgx_lasterr = ecall_key_gen_vsc(enclave_id, &ecall_retval, (uint8_t *)aes_gcm_key_buffer, aes_gcm_key_buffer_size);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
    fprintf(stderr, "[GatewayApp]: ERROR: ecall_key_gen_and_seal returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }
  
   t = clock() - t;
   double time_taken = ((double)t)/CLOCKS_PER_SEC; // calculate the elapsed time
   printf("The program took %f seconds to execute", time_taken);

  return (sgx_lasterr == SGX_SUCCESS);
}