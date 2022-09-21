#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_initPVRA_t {
	sgx_status_t ms_retval;
	sgx_report_t* ms_report;
	sgx_target_info_t* ms_target_info;
	char* ms_sealedstate;
	size_t ms_sealedstate_size;
	char* ms_enckey_signature;
	size_t ms_signature_size;
	char* ms_pub_enckey;
	size_t ms_enckey_size;
} ms_ecall_initPVRA_t;

typedef struct ms_ecall_commandPVRA_t {
	sgx_status_t ms_retval;
	char* ms_sealedstate;
	size_t ms_sealedstate_size;
	char* ms_signedFT;
	size_t ms_signedFT_size;
	char* ms_FT;
	size_t ms_FT_size;
	char* ms_eCMD;
	size_t ms_eCMD_size;
	char* ms_eAESkey;
	size_t ms_eAESkey_size;
	char* ms_cResponse;
	size_t ms_cResponse_size;
	char* ms_cRsig;
	size_t ms_cRsig_size;
	char* ms_sealedout;
	size_t ms_sealedout_size;
} ms_ecall_commandPVRA_t;

typedef struct ms_ecall_key_gen_and_seal_t {
	sgx_status_t ms_retval;
	char* ms_pubkey;
	size_t ms_pubkey_size;
	char* ms_sealedprivkey;
	size_t ms_sealedprivkey_size;
} ms_ecall_key_gen_and_seal_t;

typedef struct ms_ecall_key_gen_and_seal_all_t {
	sgx_status_t ms_retval;
	char* ms_sealedpubkey;
	size_t ms_sealedpubkey_size;
	char* ms_sealedprivkey;
	size_t ms_sealedprivkey_size;
} ms_ecall_key_gen_and_seal_all_t;

typedef struct ms_ecall_key_gen_vsc_t {
	sgx_status_t ms_retval;
	uint8_t* ms_aes_gcm_key;
	size_t ms_aes_gcm_key_size;
} ms_ecall_key_gen_vsc_t;

typedef struct ms_ecall_generate_key_ecdsa_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pub_key_buffer;
	uint8_t* ms_priv_key_buffer;
} ms_ecall_generate_key_ecdsa_t;

typedef struct ms_ecall_encrypt_aes_t {
	sgx_status_t ms_retval;
	uint8_t* ms_aes_key;
	char* ms_decMessageIn;
	size_t ms_lenIn;
	char* ms_encMessageOut;
} ms_ecall_encrypt_aes_t;

typedef struct ms_ecall_decrypt_aes_t {
	sgx_status_t ms_retval;
	uint8_t* ms_aes_key;
	char* ms_encMessageIn;
	size_t ms_lenIn;
	char* ms_decMessageOut;
} ms_ecall_decrypt_aes_t;

typedef struct ms_ecall_vsc_t {
	sgx_status_t ms_retval;
	uint8_t* ms_aes_key;
	uint8_t* ms_enc_enclave_state_in;
	size_t ms_lenInEncEnclaveState;
	uint8_t* ms_enc_command;
	size_t ms_lenInEncCommand;
	uint8_t* ms_signature;
	uint8_t* ms_pub_key_buffer;
	int ms_counter;
	int* ms_building_access;
	uint8_t* ms_enc_enclave_state_out;
} ms_ecall_vsc_t;

typedef struct ms_ecall_create_client_input_json_t {
	sgx_status_t ms_retval;
	uint8_t* ms_aes_key;
	int ms_uuid;
	int ms_command;
	char ms_result;
	uint8_t* ms_encrypted_client_input_out;
} ms_ecall_create_client_input_json_t;

typedef struct ms_ecall_create_enclave_state_json_t {
	sgx_status_t ms_retval;
	uint8_t* ms_aes_key;
	uint8_t* ms_encrypted_enclave_out;
} ms_ecall_create_enclave_state_json_t;

typedef struct ms_ecall_enclave_state_add_user_t {
	sgx_status_t ms_retval;
	uint8_t* ms_aes_key;
	uint8_t* ms_enc_enclave_state_in;
	size_t ms_lenIn;
	uint8_t* ms_new_enc_enclave_state_out;
} ms_ecall_enclave_state_add_user_t;

typedef struct ms_ecall_get_total_counter_t {
	sgx_status_t ms_retval;
	uint8_t* ms_aes_key;
	uint8_t* ms_enc_enclave_state_in;
	size_t ms_lenIn;
	int* ms_total_counter;
} ms_ecall_get_total_counter_t;

typedef struct ms_ecall_enclave_state_add_counter_mismatch_t {
	sgx_status_t ms_retval;
	uint8_t* ms_aes_key;
	int ms_delta;
	uint8_t* ms_enc_enclave_state_in;
	size_t ms_lenIn;
	uint8_t* ms_enc_cli_in;
	size_t ms_lenInCliIn;
	uint8_t* ms_new_enc_enclave_state_out;
} ms_ecall_enclave_state_add_counter_mismatch_t;

typedef struct ms_ecall_enclave_state_status_query_t {
	sgx_status_t ms_retval;
	uint8_t* ms_aes_key;
	uint8_t* ms_enc_enclave_state_in;
	size_t ms_lenIn;
	int ms_uuid;
	int* ms_building_access;
	uint8_t* ms_new_enc_enclave_state_out;
} ms_ecall_enclave_state_status_query_t;

typedef struct ms_ecall_enclave_state_status_update_t {
	sgx_status_t ms_retval;
	uint8_t* ms_aes_key;
	uint8_t* ms_enc_enclave_state_in;
	size_t ms_lenIn;
	int ms_uuid;
	char ms_result;
	uint8_t* ms_new_enc_enclave_state_out;
} ms_ecall_enclave_state_status_update_t;

typedef struct ms_ecall_hash_enclave_state_and_command_t {
	sgx_status_t ms_retval;
	uint8_t* ms_enclave_state_in;
	size_t ms_lenInEnclaveState;
	uint8_t* ms_cli_in;
	size_t ms_lenInCliIn;
	uint8_t* ms_hash;
} ms_ecall_hash_enclave_state_and_command_t;

typedef struct ms_ecall_mbed_sign_enclave_state_and_command_signature_t {
	sgx_status_t ms_retval;
	uint8_t* ms_enclave_state_in;
	size_t ms_lenInEnclaveState;
	uint8_t* ms_cli_in;
	size_t ms_lenInCliIn;
	int ms_counter;
	uint8_t* ms_priv_key_buffer;
	uint8_t* ms_pub_key_buffer;
	uint8_t* ms_signature;
} ms_ecall_mbed_sign_enclave_state_and_command_signature_t;

typedef struct ms_ecall_mbed_verify_enclave_state_and_command_signature_t {
	sgx_status_t ms_retval;
	uint8_t* ms_enclave_state_in;
	size_t ms_lenInEnclaveState;
	uint8_t* ms_cli_in;
	size_t ms_lenInCliIn;
	int ms_counter;
	uint8_t* ms_public_key_buffer;
	uint8_t* ms_signature;
} ms_ecall_mbed_verify_enclave_state_and_command_signature_t;

typedef struct ms_ecall_verify_enclave_state_and_command_signature_t {
	sgx_status_t ms_retval;
	uint8_t* ms_enclave_state_in;
	size_t ms_lenInEnclaveState;
	uint8_t* ms_cli_in;
	size_t ms_lenInCliIn;
	int ms_counter;
	uint8_t* ms_private_key_buffer;
	uint8_t* ms_signature;
	uint8_t* ms_result;
} ms_ecall_verify_enclave_state_and_command_signature_t;

typedef struct ms_ecall_sign_enclave_state_and_command_t {
	sgx_status_t ms_retval;
	uint8_t* ms_enclave_state_in;
	size_t ms_lenInEnclaveState;
	uint8_t* ms_cli_in;
	size_t ms_lenInCliIn;
	int ms_counter;
	uint8_t* ms_private_key_buffer;
	uint8_t* ms_signature;
} ms_ecall_sign_enclave_state_and_command_t;

typedef struct ms_ecall_calc_buffer_sizes_t {
	sgx_status_t ms_retval;
	size_t* ms_epubkey_size;
	size_t* ms_esealedpubkey_size;
	size_t* ms_esealedprivkey_size;
	size_t* ms_esignature_size;
} ms_ecall_calc_buffer_sizes_t;

typedef struct ms_ecall_unseal_and_sign_t {
	sgx_status_t ms_retval;
	uint8_t* ms_msg;
	uint32_t ms_msg_size;
	char* ms_sealed;
	size_t ms_sealed_size;
	char* ms_signature;
	size_t ms_signature_size;
} ms_ecall_unseal_and_sign_t;

typedef struct ms_ecall_unseal_and_quote_t {
	sgx_status_t ms_retval;
	sgx_report_t* ms_report;
	sgx_target_info_t* ms_target_info;
	char* ms_sealed;
	size_t ms_sealed_size;
	char* ms_public_key;
	size_t ms_public_key_size;
} ms_ecall_unseal_and_quote_t;

typedef struct ms_ecall_report_gen_t {
	sgx_status_t ms_retval;
	sgx_report_t* ms_report;
	sgx_target_info_t* ms_target_info;
	sgx_report_data_t ms_report_data;
} ms_ecall_report_gen_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocallbuf_t {
	int ms_size;
} ms_ocallbuf_t;

static sgx_status_t SGX_CDECL enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_rdtsc(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_rdtsc();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocallbuf(void* pms)
{
	ms_ocallbuf_t* ms = SGX_CAST(ms_ocallbuf_t*, pms);
	ocallbuf(ms->ms_size);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[3];
} ocall_table_enclave = {
	3,
	{
		(void*)enclave_ocall_print_string,
		(void*)enclave_ocall_rdtsc,
		(void*)enclave_ocallbuf,
	}
};
sgx_status_t ecall_initPVRA(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_report_t* report, sgx_target_info_t* target_info, char* sealedstate, size_t sealedstate_size, char* enckey_signature, size_t signature_size, char* pub_enckey, size_t enckey_size)
{
	sgx_status_t status;
	ms_ecall_initPVRA_t ms;
	ms.ms_report = report;
	ms.ms_target_info = target_info;
	ms.ms_sealedstate = sealedstate;
	ms.ms_sealedstate_size = sealedstate_size;
	ms.ms_enckey_signature = enckey_signature;
	ms.ms_signature_size = signature_size;
	ms.ms_pub_enckey = pub_enckey;
	ms.ms_enckey_size = enckey_size;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_commandPVRA(sgx_enclave_id_t eid, sgx_status_t* retval, char* sealedstate, size_t sealedstate_size, char* signedFT, size_t signedFT_size, char* FT, size_t FT_size, char* eCMD, size_t eCMD_size, char* eAESkey, size_t eAESkey_size, char* cResponse, size_t cResponse_size, char* cRsig, size_t cRsig_size, char* sealedout, size_t sealedout_size)
{
	sgx_status_t status;
	ms_ecall_commandPVRA_t ms;
	ms.ms_sealedstate = sealedstate;
	ms.ms_sealedstate_size = sealedstate_size;
	ms.ms_signedFT = signedFT;
	ms.ms_signedFT_size = signedFT_size;
	ms.ms_FT = FT;
	ms.ms_FT_size = FT_size;
	ms.ms_eCMD = eCMD;
	ms.ms_eCMD_size = eCMD_size;
	ms.ms_eAESkey = eAESkey;
	ms.ms_eAESkey_size = eAESkey_size;
	ms.ms_cResponse = cResponse;
	ms.ms_cResponse_size = cResponse_size;
	ms.ms_cRsig = cRsig;
	ms.ms_cRsig_size = cRsig_size;
	ms.ms_sealedout = sealedout;
	ms.ms_sealedout_size = sealedout_size;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_key_gen_and_seal(sgx_enclave_id_t eid, sgx_status_t* retval, char* pubkey, size_t pubkey_size, char* sealedprivkey, size_t sealedprivkey_size)
{
	sgx_status_t status;
	ms_ecall_key_gen_and_seal_t ms;
	ms.ms_pubkey = pubkey;
	ms.ms_pubkey_size = pubkey_size;
	ms.ms_sealedprivkey = sealedprivkey;
	ms.ms_sealedprivkey_size = sealedprivkey_size;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_key_gen_and_seal_all(sgx_enclave_id_t eid, sgx_status_t* retval, char* sealedpubkey, size_t sealedpubkey_size, char* sealedprivkey, size_t sealedprivkey_size)
{
	sgx_status_t status;
	ms_ecall_key_gen_and_seal_all_t ms;
	ms.ms_sealedpubkey = sealedpubkey;
	ms.ms_sealedpubkey_size = sealedpubkey_size;
	ms.ms_sealedprivkey = sealedprivkey;
	ms.ms_sealedprivkey_size = sealedprivkey_size;
	status = sgx_ecall(eid, 3, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_key_gen_vsc(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* aes_gcm_key, size_t aes_gcm_key_size)
{
	sgx_status_t status;
	ms_ecall_key_gen_vsc_t ms;
	ms.ms_aes_gcm_key = aes_gcm_key;
	ms.ms_aes_gcm_key_size = aes_gcm_key_size;
	status = sgx_ecall(eid, 4, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_generate_key_ecdsa(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* pub_key_buffer, uint8_t* priv_key_buffer)
{
	sgx_status_t status;
	ms_ecall_generate_key_ecdsa_t ms;
	ms.ms_pub_key_buffer = pub_key_buffer;
	ms.ms_priv_key_buffer = priv_key_buffer;
	status = sgx_ecall(eid, 5, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_encrypt_aes(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* aes_key, char* decMessageIn, size_t lenIn, char* encMessageOut)
{
	sgx_status_t status;
	ms_ecall_encrypt_aes_t ms;
	ms.ms_aes_key = aes_key;
	ms.ms_decMessageIn = decMessageIn;
	ms.ms_lenIn = lenIn;
	ms.ms_encMessageOut = encMessageOut;
	status = sgx_ecall(eid, 6, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_decrypt_aes(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* aes_key, char* encMessageIn, size_t lenIn, char* decMessageOut)
{
	sgx_status_t status;
	ms_ecall_decrypt_aes_t ms;
	ms.ms_aes_key = aes_key;
	ms.ms_encMessageIn = encMessageIn;
	ms.ms_lenIn = lenIn;
	ms.ms_decMessageOut = decMessageOut;
	status = sgx_ecall(eid, 7, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_vsc(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* aes_key, uint8_t* enc_enclave_state_in, size_t lenInEncEnclaveState, uint8_t* enc_command, size_t lenInEncCommand, uint8_t* signature, uint8_t* pub_key_buffer, int counter, int building_access[1], uint8_t* enc_enclave_state_out)
{
	sgx_status_t status;
	ms_ecall_vsc_t ms;
	ms.ms_aes_key = aes_key;
	ms.ms_enc_enclave_state_in = enc_enclave_state_in;
	ms.ms_lenInEncEnclaveState = lenInEncEnclaveState;
	ms.ms_enc_command = enc_command;
	ms.ms_lenInEncCommand = lenInEncCommand;
	ms.ms_signature = signature;
	ms.ms_pub_key_buffer = pub_key_buffer;
	ms.ms_counter = counter;
	ms.ms_building_access = (int*)building_access;
	ms.ms_enc_enclave_state_out = enc_enclave_state_out;
	status = sgx_ecall(eid, 8, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_create_client_input_json(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* aes_key, int uuid, int command, char result, uint8_t* encrypted_client_input_out)
{
	sgx_status_t status;
	ms_ecall_create_client_input_json_t ms;
	ms.ms_aes_key = aes_key;
	ms.ms_uuid = uuid;
	ms.ms_command = command;
	ms.ms_result = result;
	ms.ms_encrypted_client_input_out = encrypted_client_input_out;
	status = sgx_ecall(eid, 9, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_create_enclave_state_json(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* aes_key, uint8_t* encrypted_enclave_out)
{
	sgx_status_t status;
	ms_ecall_create_enclave_state_json_t ms;
	ms.ms_aes_key = aes_key;
	ms.ms_encrypted_enclave_out = encrypted_enclave_out;
	status = sgx_ecall(eid, 10, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_enclave_state_add_user(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* aes_key, uint8_t* enc_enclave_state_in, size_t lenIn, uint8_t* new_enc_enclave_state_out)
{
	sgx_status_t status;
	ms_ecall_enclave_state_add_user_t ms;
	ms.ms_aes_key = aes_key;
	ms.ms_enc_enclave_state_in = enc_enclave_state_in;
	ms.ms_lenIn = lenIn;
	ms.ms_new_enc_enclave_state_out = new_enc_enclave_state_out;
	status = sgx_ecall(eid, 11, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_get_total_counter(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* aes_key, uint8_t* enc_enclave_state_in, size_t lenIn, int total_counter[1])
{
	sgx_status_t status;
	ms_ecall_get_total_counter_t ms;
	ms.ms_aes_key = aes_key;
	ms.ms_enc_enclave_state_in = enc_enclave_state_in;
	ms.ms_lenIn = lenIn;
	ms.ms_total_counter = (int*)total_counter;
	status = sgx_ecall(eid, 12, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_enclave_state_add_counter_mismatch(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* aes_key, int delta, uint8_t* enc_enclave_state_in, size_t lenIn, uint8_t* enc_cli_in, size_t lenInCliIn, uint8_t* new_enc_enclave_state_out)
{
	sgx_status_t status;
	ms_ecall_enclave_state_add_counter_mismatch_t ms;
	ms.ms_aes_key = aes_key;
	ms.ms_delta = delta;
	ms.ms_enc_enclave_state_in = enc_enclave_state_in;
	ms.ms_lenIn = lenIn;
	ms.ms_enc_cli_in = enc_cli_in;
	ms.ms_lenInCliIn = lenInCliIn;
	ms.ms_new_enc_enclave_state_out = new_enc_enclave_state_out;
	status = sgx_ecall(eid, 13, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_enclave_state_status_query(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* aes_key, uint8_t* enc_enclave_state_in, size_t lenIn, int uuid, int building_access[1], uint8_t* new_enc_enclave_state_out)
{
	sgx_status_t status;
	ms_ecall_enclave_state_status_query_t ms;
	ms.ms_aes_key = aes_key;
	ms.ms_enc_enclave_state_in = enc_enclave_state_in;
	ms.ms_lenIn = lenIn;
	ms.ms_uuid = uuid;
	ms.ms_building_access = (int*)building_access;
	ms.ms_new_enc_enclave_state_out = new_enc_enclave_state_out;
	status = sgx_ecall(eid, 14, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_enclave_state_status_update(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* aes_key, uint8_t* enc_enclave_state_in, size_t lenIn, int uuid, char result, uint8_t* new_enc_enclave_state_out)
{
	sgx_status_t status;
	ms_ecall_enclave_state_status_update_t ms;
	ms.ms_aes_key = aes_key;
	ms.ms_enc_enclave_state_in = enc_enclave_state_in;
	ms.ms_lenIn = lenIn;
	ms.ms_uuid = uuid;
	ms.ms_result = result;
	ms.ms_new_enc_enclave_state_out = new_enc_enclave_state_out;
	status = sgx_ecall(eid, 15, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_hash_enclave_state_and_command(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* enclave_state_in, size_t lenInEnclaveState, uint8_t* cli_in, size_t lenInCliIn, uint8_t hash[32])
{
	sgx_status_t status;
	ms_ecall_hash_enclave_state_and_command_t ms;
	ms.ms_enclave_state_in = enclave_state_in;
	ms.ms_lenInEnclaveState = lenInEnclaveState;
	ms.ms_cli_in = cli_in;
	ms.ms_lenInCliIn = lenInCliIn;
	ms.ms_hash = (uint8_t*)hash;
	status = sgx_ecall(eid, 16, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_mbed_sign_enclave_state_and_command_signature(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* enclave_state_in, size_t lenInEnclaveState, uint8_t* cli_in, size_t lenInCliIn, int counter, uint8_t* priv_key_buffer, uint8_t* pub_key_buffer, uint8_t* signature)
{
	sgx_status_t status;
	ms_ecall_mbed_sign_enclave_state_and_command_signature_t ms;
	ms.ms_enclave_state_in = enclave_state_in;
	ms.ms_lenInEnclaveState = lenInEnclaveState;
	ms.ms_cli_in = cli_in;
	ms.ms_lenInCliIn = lenInCliIn;
	ms.ms_counter = counter;
	ms.ms_priv_key_buffer = priv_key_buffer;
	ms.ms_pub_key_buffer = pub_key_buffer;
	ms.ms_signature = signature;
	status = sgx_ecall(eid, 17, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_mbed_verify_enclave_state_and_command_signature(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* enclave_state_in, size_t lenInEnclaveState, uint8_t* cli_in, size_t lenInCliIn, int counter, uint8_t* public_key_buffer, uint8_t* signature)
{
	sgx_status_t status;
	ms_ecall_mbed_verify_enclave_state_and_command_signature_t ms;
	ms.ms_enclave_state_in = enclave_state_in;
	ms.ms_lenInEnclaveState = lenInEnclaveState;
	ms.ms_cli_in = cli_in;
	ms.ms_lenInCliIn = lenInCliIn;
	ms.ms_counter = counter;
	ms.ms_public_key_buffer = public_key_buffer;
	ms.ms_signature = signature;
	status = sgx_ecall(eid, 18, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_verify_enclave_state_and_command_signature(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* enclave_state_in, size_t lenInEnclaveState, uint8_t* cli_in, size_t lenInCliIn, int counter, uint8_t* private_key_buffer, uint8_t* signature, uint8_t* result)
{
	sgx_status_t status;
	ms_ecall_verify_enclave_state_and_command_signature_t ms;
	ms.ms_enclave_state_in = enclave_state_in;
	ms.ms_lenInEnclaveState = lenInEnclaveState;
	ms.ms_cli_in = cli_in;
	ms.ms_lenInCliIn = lenInCliIn;
	ms.ms_counter = counter;
	ms.ms_private_key_buffer = private_key_buffer;
	ms.ms_signature = signature;
	ms.ms_result = result;
	status = sgx_ecall(eid, 19, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_sign_enclave_state_and_command(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* enclave_state_in, size_t lenInEnclaveState, uint8_t* cli_in, size_t lenInCliIn, int counter, uint8_t* private_key_buffer, uint8_t* signature)
{
	sgx_status_t status;
	ms_ecall_sign_enclave_state_and_command_t ms;
	ms.ms_enclave_state_in = enclave_state_in;
	ms.ms_lenInEnclaveState = lenInEnclaveState;
	ms.ms_cli_in = cli_in;
	ms.ms_lenInCliIn = lenInCliIn;
	ms.ms_counter = counter;
	ms.ms_private_key_buffer = private_key_buffer;
	ms.ms_signature = signature;
	status = sgx_ecall(eid, 20, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_calc_buffer_sizes(sgx_enclave_id_t eid, sgx_status_t* retval, size_t* epubkey_size, size_t* esealedpubkey_size, size_t* esealedprivkey_size, size_t* esignature_size)
{
	sgx_status_t status;
	ms_ecall_calc_buffer_sizes_t ms;
	ms.ms_epubkey_size = epubkey_size;
	ms.ms_esealedpubkey_size = esealedpubkey_size;
	ms.ms_esealedprivkey_size = esealedprivkey_size;
	ms.ms_esignature_size = esignature_size;
	status = sgx_ecall(eid, 21, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_unseal_and_sign(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* msg, uint32_t msg_size, char* sealed, size_t sealed_size, char* signature, size_t signature_size)
{
	sgx_status_t status;
	ms_ecall_unseal_and_sign_t ms;
	ms.ms_msg = msg;
	ms.ms_msg_size = msg_size;
	ms.ms_sealed = sealed;
	ms.ms_sealed_size = sealed_size;
	ms.ms_signature = signature;
	ms.ms_signature_size = signature_size;
	status = sgx_ecall(eid, 22, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_unseal_and_quote(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_report_t* report, sgx_target_info_t* target_info, char* sealed, size_t sealed_size, char* public_key, size_t public_key_size)
{
	sgx_status_t status;
	ms_ecall_unseal_and_quote_t ms;
	ms.ms_report = report;
	ms.ms_target_info = target_info;
	ms.ms_sealed = sealed;
	ms.ms_sealed_size = sealed_size;
	ms.ms_public_key = public_key;
	ms.ms_public_key_size = public_key_size;
	status = sgx_ecall(eid, 23, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_report_gen(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_report_t* report, sgx_target_info_t* target_info, sgx_report_data_t report_data)
{
	sgx_status_t status;
	ms_ecall_report_gen_t ms;
	ms.ms_report = report;
	ms.ms_target_info = target_info;
	ms.ms_report_data = report_data;
	status = sgx_ecall(eid, 24, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

