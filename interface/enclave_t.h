#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_quote.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t ecall_initPVRA(sgx_report_t* report, sgx_target_info_t* target_info, char* sealedstate, size_t sealedstate_size, char* enckey_signature, size_t signature_size, char* pub_enckey, size_t enckey_size);
sgx_status_t ecall_commandPVRA(char* sealedstate, size_t sealedstate_size, char* signedFT, size_t signedFT_size, char* eCMD, size_t eCMD_size, char* eAESkey, size_t eAESkey_size, char* cResponse, size_t cResponse_size, char* cRsig, size_t cRsig_size, char* sealedout, size_t sealedout_size);
sgx_status_t ecall_key_gen_and_seal(char* pubkey, size_t pubkey_size, char* sealedprivkey, size_t sealedprivkey_size);
sgx_status_t ecall_key_gen_and_seal_all(char* sealedpubkey, size_t sealedpubkey_size, char* sealedprivkey, size_t sealedprivkey_size);
sgx_status_t ecall_key_gen_vsc(uint8_t* aes_gcm_key, size_t aes_gcm_key_size);
sgx_status_t ecall_generate_key_ecdsa(uint8_t* pub_key_buffer, uint8_t* priv_key_buffer);
sgx_status_t ecall_encrypt_aes(uint8_t* aes_key, char* decMessageIn, size_t lenIn, char* encMessageOut);
sgx_status_t ecall_decrypt_aes(uint8_t* aes_key, char* encMessageIn, size_t lenIn, char* decMessageOut);
sgx_status_t ecall_vsc(uint8_t* aes_key, uint8_t* enc_enclave_state_in, size_t lenInEncEnclaveState, uint8_t* enc_command, size_t lenInEncCommand, uint8_t* signature, uint8_t* pub_key_buffer, int counter, int building_access[1], uint8_t* enc_enclave_state_out);
sgx_status_t ecall_create_client_input_json(uint8_t* aes_key, int uuid, int command, char result, uint8_t* encrypted_client_input_out);
sgx_status_t ecall_create_enclave_state_json(uint8_t* aes_key, uint8_t* encrypted_enclave_out);
sgx_status_t ecall_enclave_state_add_user(uint8_t* aes_key, uint8_t* enc_enclave_state_in, size_t lenIn, uint8_t* new_enc_enclave_state_out);
sgx_status_t ecall_get_total_counter(uint8_t* aes_key, uint8_t* enc_enclave_state_in, size_t lenIn, int total_counter[1]);
sgx_status_t ecall_enclave_state_add_counter_mismatch(uint8_t* aes_key, int delta, uint8_t* enc_enclave_state_in, size_t lenIn, uint8_t* enc_cli_in, size_t lenInCliIn, uint8_t* new_enc_enclave_state_out);
sgx_status_t ecall_enclave_state_status_query(uint8_t* aes_key, uint8_t* enc_enclave_state_in, size_t lenIn, int uuid, int building_access[1], uint8_t* new_enc_enclave_state_out);
sgx_status_t ecall_enclave_state_status_update(uint8_t* aes_key, uint8_t* enc_enclave_state_in, size_t lenIn, int uuid, char result, uint8_t* new_enc_enclave_state_out);
sgx_status_t ecall_hash_enclave_state_and_command(uint8_t* enclave_state_in, size_t lenInEnclaveState, uint8_t* cli_in, size_t lenInCliIn, uint8_t hash[32]);
sgx_status_t ecall_mbed_sign_enclave_state_and_command_signature(uint8_t* enclave_state_in, size_t lenInEnclaveState, uint8_t* cli_in, size_t lenInCliIn, int counter, uint8_t* priv_key_buffer, uint8_t* pub_key_buffer, uint8_t* signature);
sgx_status_t ecall_mbed_verify_enclave_state_and_command_signature(uint8_t* enclave_state_in, size_t lenInEnclaveState, uint8_t* cli_in, size_t lenInCliIn, int counter, uint8_t* public_key_buffer, uint8_t* signature);
sgx_status_t ecall_verify_enclave_state_and_command_signature(uint8_t* enclave_state_in, size_t lenInEnclaveState, uint8_t* cli_in, size_t lenInCliIn, int counter, uint8_t* private_key_buffer, uint8_t* signature, uint8_t* result);
sgx_status_t ecall_sign_enclave_state_and_command(uint8_t* enclave_state_in, size_t lenInEnclaveState, uint8_t* cli_in, size_t lenInCliIn, int counter, uint8_t* private_key_buffer, uint8_t* signature);
sgx_status_t ecall_calc_buffer_sizes(size_t* epubkey_size, size_t* esealedpubkey_size, size_t* esealedprivkey_size, size_t* esignature_size);
sgx_status_t ecall_unseal_and_sign(uint8_t* msg, uint32_t msg_size, char* sealed, size_t sealed_size, char* signature, size_t signature_size);
sgx_status_t ecall_unseal_and_quote(sgx_report_t* report, sgx_target_info_t* target_info, char* sealed, size_t sealed_size, char* public_key, size_t public_key_size);
sgx_status_t ecall_report_gen(sgx_report_t* report, sgx_target_info_t* target_info, sgx_report_data_t report_data);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_rdtsc(void);
sgx_status_t SGX_CDECL ocallbuf(int size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
