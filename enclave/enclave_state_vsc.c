/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdarg.h>
#include <stdio.h>

#include "enclave.h"
#include <enclave_t.h>

#include <sgx_quote.h>
#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>
#include <sgx_trts.h>

#include <tlibc/math.h>
#include <tlibc/string.h>
#include "jsmn.h"

#define BUFLEN 2048
#define AES_128_KEY_SIZE 16
#define CLIENT_INPUT_SIZE 12
#define MAX_JSON_TOKENS 256

typedef enum { Granted, Denied } building_access;
typedef enum { Status_Update, Status_Query } Command;

struct client_input {
  int uuid;
  Command command;
  char result;
};

/**
 * This is the gateway ecall function to perform VSC status queries and status updates
 *
 * @param enclave_state_in             encrypted enclave state buffer
 * @param lenInEnclaveState            length of encrypted enclave state buffer
 * @param enc_command                  encrypted client input (command)
 * @param lenInEncCommand              length of encrypted client input (command)
 * @param pub_key_buffer               public key buffer to verify signature
 * @param signature                    signature buffer (should be the signed encrypted enclave state + client input)
 * @param counter                      counter. This is checked against the signed enclave state counter for verification 
 *                                              This counter should be equal to (signed enclave state total counter) + 1
 * @param building_access              building access buffer - used for status queries. First entry set to 0 if building access granted, 1 if building access denied.
 * 
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */
sgx_status_t ecall_vsc(uint8_t aes_key[AES_128_KEY_SIZE], uint8_t enc_enclave_state_in[BUFLEN], size_t lenInEncEnclaveState, 
  uint8_t enc_command[BUFLEN], size_t lenInEncCommand, uint8_t pub_key_buffer[BUFLEN], uint8_t signature[BUFLEN], 
  int counter, int building_access[1], 
  uint8_t enc_enclave_state_out[BUFLEN]) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle = NULL;
  if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS) {
    print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }
  uint8_t client_input_decypted[BUFLEN] = {0};
  if (ecall_decrypt_aes(aes_key, enc_command, lenInEncCommand, client_input_decypted) != SGX_SUCCESS) {
    print("\nTrustedApp: Decrypting client input failed !\n");
    goto cleanup;
  }

  /*
   * Invoke ECALL, 'ecall_verify_enclave_state_and_command_signature()'
   */
  uint8_t result[BUFLEN];
  if (ret = ecall_verify_enclave_state_and_command_signature(enc_enclave_state_in, lenInEncEnclaveState, enc_command, 
                                                    lenInEncCommand, counter, pub_key_buffer, signature, result) != SGX_SUCCESS) {
    print("\nTrustedApp: ecall_verify_enclave_state_and_command_signature() failed !\n");
    goto cleanup;
  }

  if (result[0] != 0) {
    print("\nTrustedApp: signature does not match the enclave state and command!\n");
    ret = SGX_ERROR_UNEXPECTED;
    goto cleanup;
  }

  /*
   * Invoke ECALL, 'ecall_get_total_counter()'
   */
  int mismatch = 0;
  int total_counter[1];
  if (ret = ecall_get_total_counter(aes_key, enc_enclave_state_in, lenInEncEnclaveState, total_counter) != SGX_SUCCESS) {
    print("\nTrustedApp: ecall_get_total_counter() failed !\n");
    goto cleanup;
  }
  if (total_counter[0] + 1 != counter) {
    print("\nTrustedApp: CCF counter does not match enclave state counter!\n");
    mismatch = 1;
  }

  // execute the appropriate client command 
  struct client_input * cli_out = (struct client_input *)client_input_decypted;
  uint8_t new_enc_enclave_state[BUFLEN] = {0};
  if(cli_out->command == Status_Query) {
    if (ret = ecall_enclave_state_status_query(aes_key, enc_enclave_state_in, lenInEncEnclaveState, 
                                                cli_out->uuid, building_access, new_enc_enclave_state) != SGX_SUCCESS) {
      print("\nTrustedApp: ecall_enclave_state_status_query() failed !\n");
      goto cleanup;
    }
  } else if (cli_out->command == Status_Update) {
    if (ret = ecall_enclave_state_status_update(aes_key, enc_enclave_state_in, lenInEncEnclaveState, 
                                                cli_out->uuid, cli_out->result, new_enc_enclave_state) != SGX_SUCCESS) {
      print("\nTrustedApp: ecall_enclave_state_status_update() failed !\n");
      goto cleanup;
    }
  }

  if (mismatch == 1) {
    // calculate the size of new_enc_enclave_state
    int size = BUFLEN;
    while (new_enc_enclave_state[size - 1] == 0) {
      size--;
    }
    uint8_t new_enc_enclave_state_mismatch[BUFLEN] = {0};
    if (ret = ecall_enclave_state_add_counter_mismatch(aes_key, counter - total_counter[0], new_enc_enclave_state, size, 
                                                    enc_command, lenInEncCommand, new_enc_enclave_state_mismatch) != SGX_SUCCESS) {
      print("\nTrustedApp: ecall_enclave_state_add_counter_mismatch() failed !\n"); 
      goto cleanup;                                                 
    }
    for (int i = 0; i < BUFLEN; i++) {
      enc_enclave_state_out[i] = new_enc_enclave_state_mismatch[i];
    }
  } else {
    for (int i = 0; i < BUFLEN; i++) {
      enc_enclave_state_out[i] = new_enc_enclave_state[i];
    }
  }

cleanup:
  // Step 4: Close Context.
  // free(enclave_state_str);
  // cJSON_Delete(enclave_state);
  if (p_ecc_handle != NULL) {
    sgx_ecc256_close_context(p_ecc_handle);
  }
  return ret;
}

/**
 * This creates an encrypted client input (command) JSON object
 *
 * @param aes_key                      AES-256 encryption/decryption key
 * @param uuid                         input UUID of client input (command) JSON object
 * @param command                      input command. Should correspond to either the Status_Query or Status_Update enum
 * @param result                       input test result (for status updates). Should be 0 (negative test result) or 1 (positive test result)
 * @param encrypted_client_input_out   output buffer for the encrypted client input
 * 
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */
sgx_status_t ecall_create_client_input_json(uint8_t aes_key[AES_128_KEY_SIZE], int uuid, int command, char result, uint8_t encrypted_client_input_out[BUFLEN]) {
  // Step 1: Open Context.
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle = NULL;
  if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS) {
    print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }
  struct client_input test_cli_in = {uuid, (Command) command, result};
  size_t test_cli_in_size = sizeof(test_cli_in);
  if (ecall_encrypt_aes(aes_key, (uint8_t *)(&test_cli_in), test_cli_in_size, encrypted_client_input_out) != SGX_SUCCESS) {
    print("\nTrustedApp: Encrypting client input failed !\n");
    goto cleanup;
  }
  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  // free(enclave_state_str);
  // cJSON_Delete(enclave_state);
  if (p_ecc_handle != NULL) {
    sgx_ecc256_close_context(p_ecc_handle);
  }
  return ret;
}

/**
 * This function generates and encrypts an empty enclave state (JSON object).
 * This empty state will consist of three fields:
 *  user_data - empty array
 *  total_counter - integer, increment each time that a status query or update is performed on this state. 0 initially.
 *  counter_mismatch - array of JSON objects of the form {hash(enclave_state) : counter - enclave_state.total_counter}.
 *                      Added to whenever there is a mismatch between the counter passed in to ecall_VSC and the enclave state total counter
 *
 * @param aes_key             Input parameter for 128-bit key
 * @param encrypted_enclave_out                  Output parameter for encrypted enclave
 * 
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */
sgx_status_t ecall_create_enclave_state_json(uint8_t aes_key[AES_128_KEY_SIZE], uint8_t encrypted_enclave_out[BUFLEN]) {
  // Step 1: Open Context.
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle = NULL;
  if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS) {
    print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }
  char enclave_state_str[BUFLEN] = "{\"user_data\":[], \"total_counter\": 0, \"counter_mismatch\": []}";
  int enclave_state_str_size = 0;
  while (enclave_state_str[enclave_state_str_size] != 0) {
    enclave_state_str_size++;
  }
  if (ecall_encrypt_aes(aes_key, enclave_state_str, enclave_state_str_size, encrypted_enclave_out) != SGX_SUCCESS) {
    print("\nTrustedApp: Encrypting enclave state failed !\n");
    goto cleanup;
  }
  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  // free(enclave_state_str);
  // cJSON_Delete(enclave_state);
  if (p_ecc_handle != NULL) {
    sgx_ecc256_close_context(p_ecc_handle);
  }
  return ret;
}

/**
 * This adds a user to an enclave state and encrypted the result
 *  The new user will have the UUID of the last user in the user_data array increments by 1.
 *  The new user will have no test history and a query counter of 0
 *
 * @param aes_key                      AES-256 encryption/decryption key
 * @param enc_enclave_state_in         encrypted enclave state buffer
 * @param lenIn                        length of encrypted enclave state buffer
 * @param new_enc_enclave_state_out    output buffer for new encrypted enclave state (with the added user)
 * 
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */
sgx_status_t ecall_enclave_state_add_user(uint8_t aes_key[AES_128_KEY_SIZE], uint8_t enc_enclave_state_in[BUFLEN], size_t lenIn, uint8_t new_enc_enclave_state_out[BUFLEN]) {
  // Step 1: Open Context.
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle = NULL;
  if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS) {
    print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }
  char s[BUFLEN] = {0};
  if (ecall_decrypt_aes(aes_key, enc_enclave_state_in, lenIn, s) != SGX_SUCCESS) {
    print("\nTrustedApp: Decrypting enclave state failed !\n");
    goto cleanup;
  }

  jsmn_parser p;
  jsmntok_t t[MAX_JSON_TOKENS];

  jsmn_init(&p);
  int r = jsmn_parse(&p, s, strlen(s), t, MAX_JSON_TOKENS); // "s" is the char array holding the json content
  for (int i = 0; i < r - 1; i++) {
    if (t[i].type == JSMN_STRING && t[i + 1].type == JSMN_ARRAY && t[i].end - t[i].start == 9) {
      int test = 1;
      char user_data[10] = "user_data";
      for (int j = 0; j < 9; j++) {
        if (s[t[i].start + j] != user_data[j]) {
          test = 0;
          break;
        }
      }
      if (test) {
        int array_start = t[i + 1].start;
        int array_end = t[i + 1].end;
        char new_enclave_state[BUFLEN];
        // if array is empty
        if (array_end - array_start <= 2) {
          char new_user[100] = "{\"0\":{\"test_history\":\"\", \"query_counter\": 0}}";
          for (int i = 0; i <= array_start; i++) {
            new_enclave_state[i] = s[i];
          }
          for (int i = 0; i < strlen(new_user); i++) {
            new_enclave_state[i + array_start + 1] = new_user[i];
          }
          for (int i = 0; i < strlen(s) - array_end + 1; i++) {
            new_enclave_state[i + array_start + strlen(new_user) + 1] = s[i + array_end - 1];
          }
          new_enclave_state[strlen(s) - array_end + 1 + array_start + strlen(new_user) + 1] = 0;
        } else {
          // get the ID of the last user JSON object
          int last_object_idx = i + 2;
          int index_count = i + 2;
          while (1) {
            if (t[index_count].end >= array_end) {
              break;
            }
            if (t[index_count].type == JSMN_OBJECT) {
              last_object_idx = index_count;
            }
            index_count++;
          }
          // get the value of the last user uuid (get the string of the last user uuid and cast to int)
          int last_uuid_start = t[last_object_idx - 1].start;
          int last_uuid_end = t[last_object_idx - 1].end;
          int last_uuid = 0;
          for (int j = last_uuid_start; j < last_uuid_end; j++) {
            last_uuid = 10 * last_uuid + (s[j] - '0');
          }
          // increment the last user id to get the new user id and cast back to string
          int new_user_id = last_uuid + 1;
          int num_digits = 0;
          int new_user_id_temp = new_user_id;
          while (new_user_id_temp > 0) {
            new_user_id_temp /= 10;
            num_digits++;
          }
          char new_user_id_str[num_digits + 1];
          new_user_id_str[num_digits] = 0;
          for (int j = num_digits - 1; j >= 0; --j, new_user_id /= 10) {
              new_user_id_str[j] = (new_user_id % 10) + '0';
          }
          char new_user_first_part[3] = "{\"";
          char new_user_last_part[100] = "\":{\"test_history\": \"\", \"query_counter\": 0}}";
          char new_user[100];
          for (int i = 0; i < strlen(new_user_first_part); i++) {
            new_user[i] = new_user_first_part[i];
          }
          for (int i = 0; i < strlen(new_user_id_str); i++) {
            new_user[i + strlen(new_user_first_part)] = new_user_id_str[i];
          }
          for (int i = 0; i < strlen(new_user_last_part); i++) {
            new_user[i + strlen(new_user_first_part) + strlen(new_user_id_str)] = new_user_last_part[i];
          }
          new_user[strlen(new_user_first_part) + strlen(new_user_id_str) + strlen(new_user_last_part)] = 0;
          
          // add this new_user string to the enclave state
          int new_enclave_state_index = 0;
          for (int i = 0; i < array_end - 1; i++) {
            new_enclave_state[new_enclave_state_index] = s[i];
            new_enclave_state_index++;
          }
          new_enclave_state[new_enclave_state_index] = ',';
          new_enclave_state_index++;
          new_enclave_state[new_enclave_state_index] = ' ';
          new_enclave_state_index++;
          for (int i = 0; i < strlen(new_user); i++) {
            new_enclave_state[new_enclave_state_index] = new_user[i];
            new_enclave_state_index++;
          }
          for (int i = array_end - 1; i < strlen(s); i++) {
            new_enclave_state[new_enclave_state_index] = s[i];
            new_enclave_state_index++;
          }
          new_enclave_state[new_enclave_state_index] = 0;
        }
        char new_enclave_state_enc[BUFLEN] = {0};
        if (ecall_encrypt_aes(aes_key, new_enclave_state, strlen(new_enclave_state), new_enclave_state_enc) != SGX_SUCCESS) {
          print("\nTrustedApp: Encrypting enclave state failed !\n");
          goto cleanup;
        }
        for (int j = 0; j < BUFLEN; j++) {
          new_enc_enclave_state_out[j] = new_enclave_state_enc[j];
        }
        break;
      }
    }
  }

  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  // free(enclave_state_str);
  // cJSON_Delete(enclave_state);
  if (p_ecc_handle != NULL) {
    sgx_ecc256_close_context(p_ecc_handle);
  }
  return ret;
}

/**
 * This returns the total counter from an encrypted enclave state JSON object.
 *
 * @param aes_key                      AES-256 encryption/decryption key
 * @param enc_enclave_state_in         encrypted enclave state buffer
 * @param lenIn                        length of encrypted enclave state buffer
 * @param total_counter                output buffer for total counter. The first entry will be set to the total counter's value.
 * 
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */
sgx_status_t ecall_get_total_counter(uint8_t aes_key[AES_128_KEY_SIZE], uint8_t enc_enclave_state_in[BUFLEN], size_t lenIn, int total_counter[1]) {
  // Step 1: Open Context.
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle = NULL;
  if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS) {
    print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }
  char s[BUFLEN] = {0};
  if (ecall_decrypt_aes(aes_key, enc_enclave_state_in, lenIn, s) != SGX_SUCCESS) {
    print("\nTrustedApp: Decrypting enclave state failed !\n");
    goto cleanup;
  }

  jsmn_parser p;
  jsmntok_t t[MAX_JSON_TOKENS];

  jsmn_init(&p);
  int r = jsmn_parse(&p, s, strlen(s), t, MAX_JSON_TOKENS); // "s" is the char array holding the json content
  for (int i = 0; i < r - 1; i++) {
    if (t[i].type == JSMN_STRING && t[i].end - t[i].start == 13) {
      int test = 1;
      char user_data[14] = "total_counter";
      for (int j = 0; j < 13; j++) {
        if (s[t[i].start + j] != user_data[j]) {
          test = 0;
          break;
        }
      }
      if (test) {
        int total_counter_val_index = i + 1;
        while (t[total_counter_val_index].type != JSMN_PRIMITIVE) {
          total_counter_val_index++;
        }
        int total_counter_val = 0;
        for (int j = t[total_counter_val_index].start; j < t[total_counter_val_index].end; j++) {
          total_counter_val = total_counter_val * 10 + (s[j] - '0');
        }
        total_counter[0] = total_counter_val;
        break;
      }
    }
  }

  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  // free(enclave_state_str);
  // cJSON_Delete(enclave_state);
  if (p_ecc_handle != NULL) {
    sgx_ecc256_close_context(p_ecc_handle);
  }
  return ret;
}

/**
 * This adds a counter mismatch to the counter_mismatch array in the enclave state
 * This counter mismatch is a JSON object of the form {hash(enclave_state) : delta}
 *  where delta should be (counter - enclave_state.total_counter)
 *
 * @param aes_key                      AES-256 encryption/decryption key
 * @param delta                        input delta
 * @param enclave_state_in             encrypted enclave state buffer
 * @param lenIn                        length of encrypted enclave state buffer
 * @param enc_cli_in                   encrypted client input (command)
 * @param lenInCliIn                   length of encrypted client input (command)
 * @param new_enc_enclave_state_out    output buffer for new encrypted enclave state (with added counter mismatch)
 * 
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */
sgx_status_t ecall_enclave_state_add_counter_mismatch(uint8_t aes_key[AES_128_KEY_SIZE], int delta, uint8_t enc_enclave_state_in[BUFLEN], size_t lenIn, 
                                                      uint8_t enc_cli_in[BUFLEN],size_t lenInCliIn, uint8_t new_enc_enclave_state_out[BUFLEN]) {
  // Step 1: Open Context.
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle = NULL;
  if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS) {
    print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }
  char s[BUFLEN] = {0};
  if (ecall_decrypt_aes(aes_key, enc_enclave_state_in, lenIn, s) != SGX_SUCCESS) {
    print("\nTrustedApp: Decrypting enclave state failed !\n");
    goto cleanup;
  }

  jsmn_parser p;
  jsmntok_t t[MAX_JSON_TOKENS];

  jsmn_init(&p);
  int r = jsmn_parse(&p, s, strlen(s), t, MAX_JSON_TOKENS); // "s" is the char array holding the json content
  for (int i = 0; i < r - 1; i++) {
    char user_data[] = "counter_mismatch";
    if (t[i].type == JSMN_STRING && t[i].end - t[i].start == strlen(user_data)) {
      int test = 1;
      for (int j = 0; j < strlen(user_data); j++) {
        if (s[t[i].start + j] != user_data[j]) {
          test = 0;
          break;
        }
      }
      if (test) {
        int counter_mismatch_obj_start = t[i].end;
        while (s[counter_mismatch_obj_start] != '[') {
          counter_mismatch_obj_start++;
        }
        uint8_t new_enclave_state_out[BUFLEN] = {0};
        int new_enclave_state_index = 0;
        uint8_t sha256[32] = {0};
        if (ret = (ecall_hash_enclave_state_and_command(enc_enclave_state_in, lenIn, 
                                                    enc_cli_in, lenInCliIn, sha256)) != SGX_SUCCESS) {
          goto cleanup;
        }
        // if counter mismatch array is empty
        if (s[counter_mismatch_obj_start + 1] == ']') {
          for (int j = 0; j <= counter_mismatch_obj_start; j++) {
            new_enclave_state_out[new_enclave_state_index] = s[j];
            new_enclave_state_index++;
          }
          new_enclave_state_out[new_enclave_state_index] = '{';
          new_enclave_state_index++;
          new_enclave_state_out[new_enclave_state_index] = '\"';
          new_enclave_state_index++;
          for (int j = 0; j < 32; j++) {
            // each entry in the sha256 array holds 2 hex values
            int i1 = ((sha256[j] >> 4) & 0x0F);
            int i2 = (sha256[j] & 0x0F);
            char c1 = (i1 < 10) ? i1 + '0' : (i1 - 10) + 'A'; 
            char c2 = (i2 < 10) ? i2 + '0' : (i2 - 10) + 'A';
            new_enclave_state_out[new_enclave_state_index] = c1;
            new_enclave_state_index++;
            new_enclave_state_out[new_enclave_state_index] = c2;
            new_enclave_state_index++;
          } 
          new_enclave_state_out[new_enclave_state_index] = '\"';
          new_enclave_state_index++;
          new_enclave_state_out[new_enclave_state_index] = ':';
          new_enclave_state_index++;
          if (delta < 0) {
            new_enclave_state_out[new_enclave_state_index] = '-';
            new_enclave_state_index++;
          }
          // cast the delta to string
          int num_digits = 0;
          int delta_temp = (delta < 0) ? delta * -1 : delta;
          if (delta_temp == 0) {
            num_digits = 1;
          } else {
            while (delta_temp > 0) {
              delta_temp /= 10;
              num_digits++;
            }
          }
          delta_temp = (delta < 0) ? delta * -1 : delta;;
          char delta_str[num_digits + 1];
          delta_str[num_digits] = 0;
          for (int j = num_digits - 1; j >= 0; --j, delta_temp /= 10) {
              delta_str[j] = (delta_temp % 10) + '0';
          }
          // put the delta into the counter mismatch
          for (int j = 0; j < num_digits; j++) {
            new_enclave_state_out[new_enclave_state_index] = delta_str[j];
            new_enclave_state_index++;
          }
          new_enclave_state_out[new_enclave_state_index] = '}';
          new_enclave_state_index++;
          int counter_mismatch_obj_end = counter_mismatch_obj_start + 1;
          for (int j = counter_mismatch_obj_end; j < strlen(s); j++) {
            new_enclave_state_out[new_enclave_state_index] = s[j];
            new_enclave_state_index++;
          }
        } else {
          int counter_mismatch_obj_end = counter_mismatch_obj_start + 1;
          while (s[counter_mismatch_obj_end] != ']') {
            counter_mismatch_obj_end++;
          }
          for (int j = 0; j < counter_mismatch_obj_end; j++) {
            new_enclave_state_out[new_enclave_state_index] = s[j];
            new_enclave_state_index++;
          }
          new_enclave_state_out[new_enclave_state_index] = ',';
          new_enclave_state_index++;
          new_enclave_state_out[new_enclave_state_index] = '{';
          new_enclave_state_index++;
          new_enclave_state_out[new_enclave_state_index] = '\"';
          new_enclave_state_index++;
          for (int j = 0; j < 32; j++) {
            // each entry in the sha256 array holds 2 hex values
            int i1 = ((sha256[j] >> 4) & 0x0F);
            int i2 = (sha256[j] & 0x0F);
            char c1 = (i1 < 10) ? i1 + '0' : (i1 - 10) + 'A'; 
            char c2 = (i2 < 10) ? i2 + '0' : (i2 - 10) + 'A';
            new_enclave_state_out[new_enclave_state_index] = c1;
            new_enclave_state_index++;
            new_enclave_state_out[new_enclave_state_index] = c2;
            new_enclave_state_index++;
          } 
          new_enclave_state_out[new_enclave_state_index] = '\"';
          new_enclave_state_index++;
          new_enclave_state_out[new_enclave_state_index] = ':';
          new_enclave_state_index++;
          if (delta < 0) {
            new_enclave_state_out[new_enclave_state_index] = '-';
            new_enclave_state_index++;
          }
          // cast the delta to string
          int num_digits = 0;
          int delta_temp = (delta < 0) ? delta * -1 : delta;;
          if (delta_temp == 0) {
            num_digits = 1;
          } else {
            while (delta_temp > 0) {
              delta_temp /= 10;
              num_digits++;
            }
          }
          delta_temp = (delta < 0) ? delta * -1 : delta;;
          char delta_str[num_digits + 1];
          delta_str[num_digits] = 0;
          for (int j = num_digits - 1; j >= 0; --j, delta_temp /= 10) {
              delta_str[j] = (delta_temp % 10) + '0';
          }
          // put the delta into the counter mismatch
          for (int j = 0; j < num_digits; j++) {
            new_enclave_state_out[new_enclave_state_index] = delta_str[j];
            new_enclave_state_index++;
          }
          new_enclave_state_out[new_enclave_state_index] = '}';
          new_enclave_state_index++;
          for (int j = counter_mismatch_obj_end; j < strlen(s); j++) {
            new_enclave_state_out[new_enclave_state_index] = s[j];
            new_enclave_state_index++;
          }
        }
        char new_enclave_state_enc[BUFLEN] = {0};
        if (ret = ecall_encrypt_aes(aes_key, new_enclave_state_out, new_enclave_state_index, new_enclave_state_enc) != SGX_SUCCESS) {
          print("\nTrustedApp: Encrypting enclave state failed !\n");
          goto cleanup;
        }
        for (int j = 0; j < BUFLEN; j++) {
          new_enc_enclave_state_out[j] = new_enclave_state_enc[j];
        }
      }
    }
  }

  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  // free(enclave_state_str);
  // cJSON_Delete(enclave_state);
  if (p_ecc_handle != NULL) {
    sgx_ecc256_close_context(p_ecc_handle);
  }
  return ret;
}

/**
 * This function performs a VSC status query
 * This increments the user's query counter as well as the enclave state total counter
 *
 * @param aes_key                      AES-256 encryption/decryption key
 * @param enclave_state_in             encrypted enclave state buffer
 * @param lenIn                        length of encrypted enclave state buffer
 * @param uuid                         UUID of the user that this function is performing a status query for
 * @param building_access              building access buffer. First entry set to 0 if building access granted, 1 if building access denied.
 * @param new_enc_enclave_state_out    output buffer for new encrypted enclave state (simply a copied enclave_state_in)
 * 
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */
sgx_status_t ecall_enclave_state_status_query(uint8_t aes_key[AES_128_KEY_SIZE], uint8_t enc_enclave_state_in[BUFLEN], size_t lenIn, 
                                              int uuid, int building_access[1], uint8_t new_enc_enclave_state_out[BUFLEN]) {
  // Step 1: Open Context.
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle = NULL;
  if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS) {
    print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }
  char s[BUFLEN] = {0};
  if (ecall_decrypt_aes(aes_key, enc_enclave_state_in, lenIn, s) != SGX_SUCCESS) {
    print("\nTrustedApp: Decrypting enclave state failed !\n");
    goto cleanup;
  }

  int counter_updated = 0;

  ret = SGX_SUCCESS;
  jsmn_parser p;
  jsmntok_t t[MAX_JSON_TOKENS];

  jsmn_init(&p);
  int r = jsmn_parse(&p, s, strlen(s), t, MAX_JSON_TOKENS); // "s" is the char array holding the json content
  for (int i = 0; i < r - 1; i++) {
    // cast the client input uuid to string
    int num_digits = 0;
    int new_user_id_temp = uuid;
    if (new_user_id_temp == 0) {
      num_digits = 1;
    } else {
      while (new_user_id_temp > 0) {
        new_user_id_temp /= 10;
        num_digits++;
      }
    }
    new_user_id_temp = uuid;
    char uuid_str[num_digits + 1];
    uuid_str[num_digits] = 0;
    for (int j = num_digits - 1; j >= 0; --j, new_user_id_temp /= 10) {
        uuid_str[j] = (new_user_id_temp % 10) + '0';
    }
    // find the user in the user_data array
    if (t[i].type == JSMN_STRING && t[i + 1].type == JSMN_ARRAY && t[i].end - t[i].start == 9) {
      int test = 1;
      char user_data[10] = "user_data";
      for (int j = 0; j < 9; j++) {
        if (s[t[i].start + j] != user_data[j]) {
          test = 0;
          break;
        }
      }
      if (test) {
        int array_start = t[i + 1].start;
        int array_end = t[i + 1].end;
        char new_enclave_state[BUFLEN];
        // if array is empty
        if (array_end - array_start <= 2) {
          print("\nTrustedApp: No users found in array!\n");
          goto cleanup;
        } else {
          // get the location of the user in the enclave state
          int user_object_idx = i + 2;
          int index_count = i + 2;
          int user_found = 0;
          while (1) {
            if (t[index_count].end >= array_end) {
              break;
            }
            if (t[index_count].type == JSMN_OBJECT && t[index_count + 1].type == JSMN_STRING) {
              if (strncmp(s + t[index_count + 1].start, uuid_str, t[index_count + 1].end - t[index_count + 1].start) == 0) {
                user_object_idx = index_count;
                user_found = 1;
                break;
              }
            }
            index_count++;
          }
          if (user_found == 0) {
            print("\nTrustedApp: User not found!\n");
            goto cleanup;
          }
          int test_history_index = user_object_idx;
          while (test_history_index < r && (t[test_history_index].type != JSMN_STRING 
          || strncmp(s + t[test_history_index].start, "test_history", strlen("test_history")) != 0)) {
            test_history_index++;
          }
          if (test_history_index == r) {
            print("\nTrustedApp: Test history not found! \n");
            goto cleanup;
          }
          int test_history_string_index = test_history_index + 1;
          int test_history_string_start = t[test_history_string_index].start;
          int test_history_string_end = t[test_history_string_index].end;

          if (test_history_string_end - test_history_string_start < 2) {
            print("\nTrustedApp: Not enough test history! Building access denied. \n");
            building_access[0] = (int)Denied;
          } else {
            if (s[t[test_history_string_index].end - 1] == '0' && s[t[test_history_string_index].end - 2] == '0') {
              print("\nTrustedApp: Building access granted. \n");
              building_access[0] = (int)Granted;
            } else {
              print("\nTrustedApp: Recent positive tests. Building access denied. \n");
              building_access[0] = (int)Denied;
            }
          }

          // get the user's query counter and increment by 1
          int query_counter_index = test_history_index;
          while (query_counter_index < r && (t[query_counter_index].type != JSMN_STRING 
          || strncmp(s + t[query_counter_index].start, "query_counter", strlen("query_counter")) != 0)) {
            query_counter_index++;
          }
          if (query_counter_index == r) {
            print("\nTrustedApp: Internal error! \n");
            goto cleanup;
          }
          int query_counter_string_index = query_counter_index + 1;
          int query_counter_string_start = t[query_counter_string_index].start;
          int query_counter_string_end = t[query_counter_string_index].end;
          int query_counter = 0;
          for (int j = t[query_counter_string_index].start; j < t[query_counter_string_index].end; j++) {
            query_counter = query_counter * 10 + (s[j] - '0');
          }
          query_counter++;
          int num_digits = 0;
          int new_query_counter_temp = query_counter;
          if (new_query_counter_temp == 0) {
            num_digits = 1;
          } else {
            while (new_query_counter_temp > 0) {
              new_query_counter_temp /= 10;
              num_digits++;
            }
          }
          char query_counter_str[num_digits + 1];
          query_counter_str[num_digits] = 0;
          for (int j = num_digits - 1; j >= 0; --j, query_counter /= 10) {
              query_counter_str[j] = (query_counter % 10) + '0';
          }

          // get the total counter and increment by 1
          int total_counter_index = query_counter_string_index;
          while (total_counter_index < r && (t[total_counter_index].type != JSMN_STRING 
          || strncmp(s + t[total_counter_index].start, "total_counter", strlen("total_counter")) != 0)) {
            total_counter_index++;
          }
          if (total_counter_index == r) {
            print("\nTrustedApp: Internal error! \n");
            goto cleanup;
          }
          int total_counter_string_index = total_counter_index + 1;
          int total_counter_string_start = t[total_counter_string_index].start;
          int total_counter_string_end = t[total_counter_string_index].end;
          int total_counter = 0;
          for (int j = t[total_counter_string_index].start; j < t[total_counter_string_index].end; j++) {
            total_counter = total_counter * 10 + (s[j] - '0');
          }
          total_counter++;
          num_digits = 0;
          int new_total_counter_temp = total_counter;
          if (new_total_counter_temp == 0) {
            num_digits = 1;
          } else {
            while (new_total_counter_temp > 0) {
              new_total_counter_temp /= 10;
              num_digits++;
            }
          }
          char total_counter_str[num_digits + 1];
          total_counter_str[num_digits] = 0;
          for (int j = num_digits - 1; j >= 0; --j, total_counter /= 10) {
              total_counter_str[j] = (total_counter % 10) + '0';
          }

          // update the enclave state
          int new_enclave_state_index = 0;
          for (int j = 0; j < test_history_string_end; j++) {
            new_enclave_state[new_enclave_state_index] = s[j];
            new_enclave_state_index++;
          }
          for (int j = test_history_string_end; j < query_counter_string_start; j++) {
            new_enclave_state[new_enclave_state_index] = s[j];
            new_enclave_state_index++;
          }
          for (int j = 0; j < strlen(query_counter_str); j++) {
            new_enclave_state[new_enclave_state_index] = query_counter_str[j];
            new_enclave_state_index++;
          }
          for (int j = query_counter_string_end; j < total_counter_string_start; j++) {
            new_enclave_state[new_enclave_state_index] = s[j];
            new_enclave_state_index++;
          }
          for (int j = 0; j < strlen(total_counter_str); j++) {
            new_enclave_state[new_enclave_state_index] = total_counter_str[j];
            new_enclave_state_index++;
          }
          for (int j = total_counter_string_end; j < strlen(s); j++) {
            new_enclave_state[new_enclave_state_index] = s[j];
            new_enclave_state_index++;
          }
          char new_enclave_state_enc[BUFLEN] = {0};
          if (ret = ecall_encrypt_aes(aes_key, new_enclave_state, strlen(new_enclave_state), new_enclave_state_enc) != SGX_SUCCESS) {
            print("\nTrustedApp: Encrypting enclave state failed !\n");
            goto cleanup;
          }
          for (int j = 0; j < BUFLEN; j++) {
            new_enc_enclave_state_out[j] = new_enclave_state_enc[j];
          }
          counter_updated = 1;
        }
        break;
      }
    }
  }

  ret = SGX_SUCCESS;

cleanup:
  if (counter_updated == 0) {
    for (int i = 0; i < lenIn; i++) {
      new_enc_enclave_state_out[i] = enc_enclave_state_in[i];
    }
  }
  // Step 4: Close Context.
  // free(enclave_state_str);
  // cJSON_Delete(enclave_state);
  if (p_ecc_handle != NULL) {
    sgx_ecc256_close_context(p_ecc_handle);
  }
  return ret;
}

/**
 * This function performs a VSC status update
 *  This appends to the appropriate user's test history and increments the user's query counter as well as the enclave state total counter
 *
 * @param aes_key                      AES-256 encryption/decryption key
 * @param enclave_state_in             encrypted enclave state buffer
 * @param lenIn                        length of encrypted enclave state buffer
 * @param uuid                         UUID of the user that this function is performing a status query for
 * @param result                       input test result. Should be 0 (negative test result) or 1 (positive test result)
 * @param new_enc_enclave_state_out    output buffer for new encrypted enclave state (with new test result)
 * 
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */
sgx_status_t ecall_enclave_state_status_update(uint8_t aes_key[AES_128_KEY_SIZE], uint8_t enc_enclave_state_in[BUFLEN], size_t lenIn, 
                                              int uuid, char result, uint8_t new_enc_enclave_state_out[BUFLEN]) {
  // Step 1: Open Context.
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle = NULL;
  if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS) {
    print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }
  char s[BUFLEN] = {0};
  if (ecall_decrypt_aes(aes_key, enc_enclave_state_in, lenIn, s) != SGX_SUCCESS) {
    print("\nTrustedApp: Decrypting enclave state failed !\n");
    goto cleanup;
  }

  char new_enclave_state[BUFLEN] = {0};
  int updated_user = 0;

  ret = SGX_SUCCESS;
  jsmn_parser p;
  jsmntok_t t[MAX_JSON_TOKENS];

  jsmn_init(&p);
  int r = jsmn_parse(&p, s, strlen(s), t, MAX_JSON_TOKENS); // "s" is the char array holding the json content
  for (int i = 0; i < r - 1; i++) {
    // cast the client input uuid to string
    int num_digits = 0;
    int new_user_id_temp = uuid;
    if (new_user_id_temp == 0) {
      num_digits = 1;
    } else {
      while (new_user_id_temp > 0) {
        new_user_id_temp /= 10;
        num_digits++;
      }
    }
    new_user_id_temp = uuid;
    char uuid_str[num_digits + 1];
    uuid_str[num_digits] = 0;
    for (int j = num_digits - 1; j >= 0; --j, new_user_id_temp /= 10) {
        uuid_str[j] = (new_user_id_temp % 10) + '0';
    }
    // find the user in the user_data array
    if (t[i].type == JSMN_STRING && t[i + 1].type == JSMN_ARRAY && t[i].end - t[i].start == 9) {
      int test = 1;
      char user_data[10] = "user_data";
      for (int j = 0; j < 9; j++) {
        if (s[t[i].start + j] != user_data[j]) {
          test = 0;
          break;
        }
      }
      if (test) {
        int array_start = t[i + 1].start;
        int array_end = t[i + 1].end;
        char new_enclave_state[BUFLEN] = {0};
        // if array is empty
        if (array_end - array_start <= 2) {
          print("\nTrustedApp: No users found in array!\n");
          goto cleanup;
        } else {
          // get the location of the user in the enclave state
          int user_object_idx = i + 2;
          int index_count = i + 2;
          int user_found = 0;
          while (1) {
            if (t[index_count].end >= array_end) {
              break;
            }
            if (t[index_count].type == JSMN_OBJECT && t[index_count + 1].type == JSMN_STRING) {
              if (strncmp(s + t[index_count + 1].start, uuid_str, t[index_count + 1].end - t[index_count + 1].start) == 0) {
                user_object_idx = index_count;
                user_found = 1;
                break;
              }
            }
            index_count++;
          }
          if (user_found == 0) {
            print("\nTrustedApp: User not found!\n");
            goto cleanup;
          }
          print("\n User found ecall_status_update! \n");
          // get the string indices of the user's test history
          int test_history_index = user_object_idx;
          while (test_history_index < r && (t[test_history_index].type != JSMN_STRING 
          || strncmp(s + t[test_history_index].start, "test_history", strlen("test_history")) != 0)) {
            test_history_index++;
          }
          if (test_history_index == r) {
            print("\nTrustedApp: Test history not found! \n");
            goto cleanup;
          }
          int test_history_string_index = test_history_index + 1;
          int test_history_string_start = t[test_history_string_index].start;
          int test_history_string_end = t[test_history_string_index].end;
          
          // get the user's query counter and increment by 1
          int query_counter_index = test_history_index;
          while (query_counter_index < r && (t[query_counter_index].type != JSMN_STRING 
          || strncmp(s + t[query_counter_index].start, "query_counter", strlen("query_counter")) != 0)) {
            query_counter_index++;
          }
          if (query_counter_index == r) {
            print("\nTrustedApp: Internal error! \n");
            goto cleanup;
          }
          int query_counter_string_index = query_counter_index + 1;
          int query_counter_string_start = t[query_counter_string_index].start;
          int query_counter_string_end = t[query_counter_string_index].end;
          int query_counter = 0;
          for (int j = t[query_counter_string_index].start; j < t[query_counter_string_index].end; j++) {
            query_counter = query_counter * 10 + (s[j] - '0');
          }
          query_counter++;
          int num_digits = 0;
          int new_query_counter_temp = query_counter;
          if (new_query_counter_temp == 0) {
            num_digits = 1;
          } else {
            while (new_query_counter_temp > 0) {
              new_query_counter_temp /= 10;
              num_digits++;
            }
          }
          char query_counter_str[num_digits + 1];
          query_counter_str[num_digits] = 0;
          for (int j = num_digits - 1; j >= 0; --j, query_counter /= 10) {
              query_counter_str[j] = (query_counter % 10) + '0';
          }

          // get the total counter and increment by 1
          int total_counter_index = query_counter_string_index;
          while (total_counter_index < r && (t[total_counter_index].type != JSMN_STRING 
          || strncmp(s + t[total_counter_index].start, "total_counter", strlen("total_counter")) != 0)) {
            total_counter_index++;
          }
          if (total_counter_index == r) {
            print("\nTrustedApp: Internal error! \n");
            goto cleanup;
          }
          int total_counter_string_index = total_counter_index + 1;
          int total_counter_string_start = t[total_counter_string_index].start;
          int total_counter_string_end = t[total_counter_string_index].end;
          int total_counter = 0;
          for (int j = t[total_counter_string_index].start; j < t[total_counter_string_index].end; j++) {
            total_counter = total_counter * 10 + (s[j] - '0');
          }
          total_counter++;
          num_digits = 0;
          int new_total_counter_temp = total_counter;
          if (new_total_counter_temp == 0) {
            num_digits = 1;
          } else {
            while (new_total_counter_temp > 0) {
              new_total_counter_temp /= 10;
              num_digits++;
            }
          }
          char total_counter_str[num_digits + 1];
          total_counter_str[num_digits] = 0;
          for (int j = num_digits - 1; j >= 0; --j, total_counter /= 10) {
              total_counter_str[j] = (total_counter % 10) + '0';
          }
          
          // update the enclave state
          int new_enclave_state_index = 0;
          for (int j = 0; j < test_history_string_end; j++) {
            new_enclave_state[new_enclave_state_index] = s[j];
            new_enclave_state_index++;
          }
          new_enclave_state[new_enclave_state_index] = result;
          new_enclave_state_index++;
          for (int j = test_history_string_end; j < query_counter_string_start; j++) {
            new_enclave_state[new_enclave_state_index] = s[j];
            new_enclave_state_index++;
          }
          for (int j = 0; j < strlen(query_counter_str); j++) {
            new_enclave_state[new_enclave_state_index] = query_counter_str[j];
            new_enclave_state_index++;
          }
          for (int j = query_counter_string_end; j < total_counter_string_start; j++) {
            new_enclave_state[new_enclave_state_index] = s[j];
            new_enclave_state_index++;
          }
          for (int j = 0; j < strlen(total_counter_str); j++) {
            new_enclave_state[new_enclave_state_index] = total_counter_str[j];
            new_enclave_state_index++;
          }
          for (int j = total_counter_string_end; j < strlen(s); j++) {
            new_enclave_state[new_enclave_state_index] = s[j];
            new_enclave_state_index++;
          }
          char new_enclave_state_enc[BUFLEN] = {0};
          if (ret = ecall_encrypt_aes(aes_key, new_enclave_state, strlen(new_enclave_state), new_enclave_state_enc) != SGX_SUCCESS) {
            print("\nTrustedApp: Encrypting enclave state failed !\n");
            goto cleanup;
          }
          for (int j = 0; j < BUFLEN; j++) {
            new_enc_enclave_state_out[j] = new_enclave_state_enc[j];
          }
          updated_user = 1;
        }
        break;
      }
    }
  }


  ret = SGX_SUCCESS;

cleanup:
  if (updated_user == 0) {
    for (int j = 0; j < BUFLEN; j++) {
      new_enc_enclave_state_out[j] = enc_enclave_state_in[j];
    }
  }
  // Step 4: Close Context.
  // free(enclave_state_str);
  // cJSON_Delete(enclave_state);
  if (p_ecc_handle != NULL) {
    sgx_ecc256_close_context(p_ecc_handle);
  }
  return ret;
}

/**
 * This function generates a SHA-256 hash of an encrypted enclave state and client input (command)
 *  The hash is of a combined array of the enclave state data followed by the client input data
 *
 * @param enclave_state_in             encrypted enclave state buffer
 * @param lenInEnclaveState            length of encrypted enclave state buffer
 * @param enc_cli_in                   encrypted client input (command)
 * @param lenInCliIn                   length of encrypted client input (command)
 * @param hash                         output buffer for the hash of the enclave state and client input
 * 
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */
sgx_status_t ecall_hash_enclave_state_and_command(uint8_t enclave_state_in[BUFLEN], size_t lenInEnclaveState, 
                                                  uint8_t cli_in[BUFLEN], size_t lenInCliIn, uint8_t hash[32]) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  // combine the enclave state data and client input (command) data into one array
  uint8_t enclave_state_client_input_combined[BUFLEN] = {0};
  int combined_index = 0;
  for (int i = 0; i < lenInEnclaveState; i++) {
    enclave_state_client_input_combined[combined_index] = enclave_state_in[i];
    combined_index++;
  }
  for (int i = 0; i < lenInCliIn; i++) {
    enclave_state_client_input_combined[combined_index] = cli_in[i];
    combined_index++;
  }
  int len_combined = combined_index;
  sgx_sha_state_handle_t sha_handle = NULL;

  // set up the sgx sha-256 handle and hash the combined array
  if ((ret = sgx_sha256_init(&sha_handle) != SGX_SUCCESS)) {
    print("\nTrustedApp: sgx_sha256_init() failed !\n");
    goto cleanup;
  }

  if ((ret = sgx_sha256_update((uint8_t *)enclave_state_client_input_combined, len_combined, sha_handle) != SGX_SUCCESS)) {
    print("\nTrustedApp: sgx_sha256_update() failed !\n");
    goto cleanup;
  }

  if ((ret = sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t *)hash) != SGX_SUCCESS)) {
    print("\nTrustedApp: sgx_sha256_get_hash() failed !\n");
    goto cleanup;
  }

  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  // free(enclave_state_str);
  // cJSON_Delete(enclave_state);
  if (sha_handle != NULL) {
    sgx_sha256_close(sha_handle);
  }
  return ret;
}

