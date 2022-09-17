#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <enclave_u.h> /* For sgx_enclave_id_t */

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>

#include "cJSON.h"
#include "app.h"

typedef enum { Granted, Denied } building_access;
typedef enum { Status_Update, Status_Query } Command;

struct client_input {
  int uuid;
  Command command;
  char result;
};

struct signed_counter_update {
  int signature;
  uint8_t enc_data_command_hash[32];
  int value;
};

bool enclave_vsc(char  * enc_enclave_state_txt_file, char  * enc_client_input_txt_file, 
                char * signature_file, char * pub_key_txt_file, int counter) {
  sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;
  
  uint8_t enc_enclave_state[2048] = {0};
  uint8_t enc_client_input_state[2048] = {0};
  uint8_t signature[2048] = {0};
  uint8_t pub_key_buffer[2048] = {0};
  size_t enc_enclave_state_size;
  size_t enc_client_input_size;
  size_t signature_size;
  size_t pub_key_size;
  load_text(enc_enclave_state_txt_file, enc_enclave_state, &enc_enclave_state_size);
  load_text(enc_client_input_txt_file, enc_client_input_state, &enc_client_input_size);
  load_text(signature_file, signature, &signature_size);
  load_text(pub_key_txt_file, pub_key_buffer, &pub_key_size); 
  

  /*
   * Invoke ECALL, 'ecall_verify_enclave_state_and_command_signature()'
   */
      clock_t t;
   t = clock();
   
  uint8_t building_access[1] = {0};
  uint8_t new_enc_enclave_state[2048] = {0};
  sgx_lasterr = ecall_vsc(enclave_id, &ecall_retval, (uint8_t *)aes_gcm_key_buffer, enc_enclave_state, enc_enclave_state_size,
                            enc_client_input_state, enc_client_input_size, pub_key_buffer, signature, counter, 
                            building_access, new_enc_enclave_state);
                            
                               t = clock() - t;
   double time_taken = ((double)t)/CLOCKS_PER_SEC; // calculate the elapsed time
   printf("The program took %f seconds to execute", time_taken);
   
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
    fprintf(stderr, "[GatewayApp]: ERROR: ecall_verify_enclave_state_and_command_signature returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }

  copy_to_encrypted_buffer(new_enc_enclave_state, 2048);
  save_text(encrypted_message_buffer, get_encrypted_buffer_size(), enc_enclave_state_txt_file);

  return (sgx_lasterr == SGX_SUCCESS);
}

bool create_client_input_json(char * txt_file, int uuid, int command, char result) {
  sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

  printf("[GatewayApp]: Calling enclave to encrypt enclave state JSON\n");

  /*
   * Invoke ECALL, 'ecall_key_gen_vsc()', to generate a key
   */
  sgx_lasterr = ecall_create_client_input_json(enclave_id, &ecall_retval, (uint8_t *)aes_gcm_key_buffer, 
                                              uuid, command, result, encrypted_message_buffer);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
    fprintf(stderr, "[GatewayApp]: ERROR: ecall_create_enclave_state_json returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }
  save_text(encrypted_message_buffer, get_encrypted_buffer_size(), txt_file);
  
  return (sgx_lasterr == SGX_SUCCESS);
}


bool create_enclave_state_json(char * txt_file) {
  sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

  printf("[GatewayApp]: Calling enclave to encrypt enclave state JSON\n");

  /*
   * Invoke ECALL, 'ecall_key_gen_vsc()', to generate a key
   */
      clock_t t;
   t = clock();
   
  sgx_lasterr = ecall_create_enclave_state_json(enclave_id, &ecall_retval, (uint8_t *)aes_gcm_key_buffer, encrypted_message_buffer);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
    fprintf(stderr, "[GatewayApp]: ERROR: ecall_create_enclave_state_json returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }
     t = clock() - t;
   double time_taken = ((double)t)/CLOCKS_PER_SEC; // calculate the elapsed time
   printf("The program took %f seconds to execute", time_taken);
   
  save_text(encrypted_message_buffer, get_encrypted_buffer_size(), txt_file);
  
  return (sgx_lasterr == SGX_SUCCESS);
}

bool enclave_enclave_state_add_counter_mismatch(char * enc_enclave_state_txt_file, char  * enc_client_input_txt_file, int delta) {
  sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

  printf("[GatewayApp]: Calling enclave to add counter mismatch!\n");

  uint8_t enc_enclave_state[2048];
  uint8_t enc_client_input_state[2048];
  size_t enc_enclave_state_size;
  size_t enc_client_input_size;
  load_text(enc_enclave_state_txt_file, enc_enclave_state, &enc_enclave_state_size);
  load_text(enc_client_input_txt_file, enc_client_input_state, &enc_client_input_size);

  /*
   * Invoke ECALL, 'ecall_key_gen_vsc()', to generate a key
   */
  sgx_lasterr = ecall_enclave_state_add_counter_mismatch(enclave_id, &ecall_retval, (uint8_t *)aes_gcm_key_buffer, 
                  delta, enc_enclave_state, enc_enclave_state_size, enc_client_input_state, 
                  enc_client_input_size, encrypted_message_buffer);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
    fprintf(stderr, "[GatewayApp]: ERROR: ecall_create_enclave_state_json returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }

  save_text(encrypted_message_buffer, get_encrypted_buffer_size(), enc_enclave_state_txt_file);
  
  return (sgx_lasterr == SGX_SUCCESS);
}

bool encrypt_and_save_json_enclave_state(char * txt_file_out) {
  bool success = (
    copy_to_decrypted_buffer(json_enclave_state_buffer, strlen(json_enclave_state_buffer)) &&
    enclave_encrypt_aes() &&
    save_text(encrypted_message_buffer, get_encrypted_buffer_size(), txt_file_out)
  );
  return success;
}

bool load_and_decrypt_json_enclave_state(char * txt_file_in) {
  size_t text_size;
  char text[encrypt_decrypt_message_size];
  memset(text, 0, encrypt_decrypt_message_size);

  bool success = (
    load_text(txt_file_in, text, &text_size) &&
    copy_to_encrypted_buffer(text, text_size) &&
    enclave_decrypt_aes() &&
    memset(json_enclave_state_buffer, 0, strlen(decrypted_message_buffer) + 1) &&
    memcpy(json_enclave_state_buffer, decrypted_message_buffer, strlen(decrypted_message_buffer))
  );
  return success;
}

bool add_user_json_enclave_state(char * txt_file) {
  sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

  printf("[GatewayApp]: Calling enclave to add user to enclave state JSON\n");
  size_t text_size;
  char text[encrypt_decrypt_message_size];
  memset(text, 0, encrypt_decrypt_message_size);
  load_text(txt_file, text, &text_size);
  copy_to_encrypted_buffer(text, text_size);
  /*
   * Invoke ECALL, 'ecall_enclave_state_add_user()'
   */
  char out[2048];
  sgx_lasterr = ecall_enclave_state_add_user(enclave_id, &ecall_retval, (uint8_t *)aes_gcm_key_buffer, encrypted_message_buffer, get_encrypted_buffer_size(), out);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
    fprintf(stderr, "[GatewayApp]: ERROR: ecall_create_enclave_state_json returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }
  copy_to_encrypted_buffer(out, 2048);
  save_text(encrypted_message_buffer, get_encrypted_buffer_size(), txt_file);

  return (sgx_lasterr == SGX_SUCCESS);
}

bool test_ecall_vsc(char * enc_enclave_state_txt_file) {
  sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

  char test_enclave_state[2048] = "{\"user_data\":[], \"total_counter\": 0, \"counter_mismatch\": {\"inputHash0\":0}}";
  struct client_input test_cli_in = {0, Status_Query, '0'};
  uint8_t hash[32] = {0};
  ecall_hash_enclave_state_and_command(enclave_id, &ecall_retval, test_enclave_state, strlen(test_enclave_state), (uint8_t *)(&test_cli_in), 12, hash);
  printf("\n hash \n");
  for (int i = 0; i < 32; i++) {
    printf("%x", hash[i]);
  }
  printf("\n");

  struct client_input cli_in = {0, Status_Query, '0'};
  copy_to_decrypted_buffer((uint8_t *)(&cli_in), sizeof(cli_in));
  enclave_encrypt_aes();
  size_t client_input_enc_size = get_encrypted_buffer_size();
  uint8_t client_input_enc[2048] = {0};
  memcpy(client_input_enc, encrypted_message_buffer, client_input_enc_size);

  size_t enc_enclave_state_text_size;
  char text[encrypt_decrypt_message_size];
  memset(text, 0, encrypt_decrypt_message_size);
  load_text(enc_enclave_state_txt_file, text, &enc_enclave_state_text_size);
  copy_to_encrypted_buffer(text, enc_enclave_state_text_size);
  uint8_t signed_counter_update[2048];

  int building_access[1];
  uint8_t enc_enclave_state_out[2048];

  // sgx_lasterr = ecall_vsc(enclave_id, &ecall_retval, (uint8_t *)aes_gcm_key_buffer, encrypted_message_buffer, enc_enclave_state_text_size, 
  // client_input_enc, client_input_enc_size, signed_counter_update, building_access, enc_enclave_state_out);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
    fprintf(stderr, "[GatewayApp]: ERROR: ecall_vsc returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }
  if (cli_in.command == Status_Update) {
    copy_to_encrypted_buffer(enc_enclave_state_out, 2048);
  } else {
    copy_to_encrypted_buffer(text, enc_enclave_state_text_size);
  }
  save_text(encrypted_message_buffer, get_encrypted_buffer_size(), enc_enclave_state_txt_file);

  if (cli_in.command == Status_Query) {
    printf("\n Building access for user %u is %u \n", cli_in.uuid, building_access[0]);
  }

  return (sgx_lasterr == SGX_SUCCESS);
};