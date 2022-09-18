#include "enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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
	char* ms_eCMD;
	size_t ms_eCMD_size;
	char* ms_eAESkey;
	size_t ms_eAESkey_size;
	char* ms_cResponse;
	size_t ms_cResponse_size;
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

static sgx_status_t SGX_CDECL sgx_ecall_initPVRA(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_initPVRA_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_initPVRA_t* ms = SGX_CAST(ms_ecall_initPVRA_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_report = ms->ms_report;
	size_t _len_report = sizeof(sgx_report_t);
	sgx_report_t* _in_report = NULL;
	sgx_target_info_t* _tmp_target_info = ms->ms_target_info;
	size_t _len_target_info = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_target_info = NULL;
	char* _tmp_sealedstate = ms->ms_sealedstate;
	size_t _tmp_sealedstate_size = ms->ms_sealedstate_size;
	size_t _len_sealedstate = _tmp_sealedstate_size;
	char* _in_sealedstate = NULL;
	char* _tmp_enckey_signature = ms->ms_enckey_signature;
	size_t _tmp_signature_size = ms->ms_signature_size;
	size_t _len_enckey_signature = _tmp_signature_size;
	char* _in_enckey_signature = NULL;
	char* _tmp_pub_enckey = ms->ms_pub_enckey;
	size_t _tmp_enckey_size = ms->ms_enckey_size;
	size_t _len_pub_enckey = _tmp_enckey_size;
	char* _in_pub_enckey = NULL;

	CHECK_UNIQUE_POINTER(_tmp_report, _len_report);
	CHECK_UNIQUE_POINTER(_tmp_target_info, _len_target_info);
	CHECK_UNIQUE_POINTER(_tmp_sealedstate, _len_sealedstate);
	CHECK_UNIQUE_POINTER(_tmp_enckey_signature, _len_enckey_signature);
	CHECK_UNIQUE_POINTER(_tmp_pub_enckey, _len_pub_enckey);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_report != NULL && _len_report != 0) {
		if ((_in_report = (sgx_report_t*)malloc(_len_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_report, 0, _len_report);
	}
	if (_tmp_target_info != NULL && _len_target_info != 0) {
		_in_target_info = (sgx_target_info_t*)malloc(_len_target_info);
		if (_in_target_info == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_target_info, _len_target_info, _tmp_target_info, _len_target_info)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sealedstate != NULL && _len_sealedstate != 0) {
		if ( _len_sealedstate % sizeof(*_tmp_sealedstate) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealedstate = (char*)malloc(_len_sealedstate)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealedstate, 0, _len_sealedstate);
	}
	if (_tmp_enckey_signature != NULL && _len_enckey_signature != 0) {
		if ( _len_enckey_signature % sizeof(*_tmp_enckey_signature) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_enckey_signature = (char*)malloc(_len_enckey_signature)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_enckey_signature, 0, _len_enckey_signature);
	}
	if (_tmp_pub_enckey != NULL && _len_pub_enckey != 0) {
		if ( _len_pub_enckey % sizeof(*_tmp_pub_enckey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_pub_enckey = (char*)malloc(_len_pub_enckey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pub_enckey, 0, _len_pub_enckey);
	}

	ms->ms_retval = ecall_initPVRA(_in_report, _in_target_info, _in_sealedstate, _tmp_sealedstate_size, _in_enckey_signature, _tmp_signature_size, _in_pub_enckey, _tmp_enckey_size);
	if (_in_report) {
		if (memcpy_s(_tmp_report, _len_report, _in_report, _len_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_sealedstate) {
		if (memcpy_s(_tmp_sealedstate, _len_sealedstate, _in_sealedstate, _len_sealedstate)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_enckey_signature) {
		if (memcpy_s(_tmp_enckey_signature, _len_enckey_signature, _in_enckey_signature, _len_enckey_signature)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_pub_enckey) {
		if (memcpy_s(_tmp_pub_enckey, _len_pub_enckey, _in_pub_enckey, _len_pub_enckey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_report) free(_in_report);
	if (_in_target_info) free(_in_target_info);
	if (_in_sealedstate) free(_in_sealedstate);
	if (_in_enckey_signature) free(_in_enckey_signature);
	if (_in_pub_enckey) free(_in_pub_enckey);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_commandPVRA(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_commandPVRA_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_commandPVRA_t* ms = SGX_CAST(ms_ecall_commandPVRA_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_sealedstate = ms->ms_sealedstate;
	size_t _tmp_sealedstate_size = ms->ms_sealedstate_size;
	size_t _len_sealedstate = _tmp_sealedstate_size;
	char* _in_sealedstate = NULL;
	char* _tmp_signedFT = ms->ms_signedFT;
	size_t _tmp_signedFT_size = ms->ms_signedFT_size;
	size_t _len_signedFT = _tmp_signedFT_size;
	char* _in_signedFT = NULL;
	char* _tmp_eCMD = ms->ms_eCMD;
	size_t _tmp_eCMD_size = ms->ms_eCMD_size;
	size_t _len_eCMD = _tmp_eCMD_size;
	char* _in_eCMD = NULL;
	char* _tmp_eAESkey = ms->ms_eAESkey;
	size_t _tmp_eAESkey_size = ms->ms_eAESkey_size;
	size_t _len_eAESkey = _tmp_eAESkey_size;
	char* _in_eAESkey = NULL;
	char* _tmp_cResponse = ms->ms_cResponse;
	size_t _tmp_cResponse_size = ms->ms_cResponse_size;
	size_t _len_cResponse = _tmp_cResponse_size;
	char* _in_cResponse = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealedstate, _len_sealedstate);
	CHECK_UNIQUE_POINTER(_tmp_signedFT, _len_signedFT);
	CHECK_UNIQUE_POINTER(_tmp_eCMD, _len_eCMD);
	CHECK_UNIQUE_POINTER(_tmp_eAESkey, _len_eAESkey);
	CHECK_UNIQUE_POINTER(_tmp_cResponse, _len_cResponse);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealedstate != NULL && _len_sealedstate != 0) {
		if ( _len_sealedstate % sizeof(*_tmp_sealedstate) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealedstate = (char*)malloc(_len_sealedstate);
		if (_in_sealedstate == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealedstate, _len_sealedstate, _tmp_sealedstate, _len_sealedstate)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_signedFT != NULL && _len_signedFT != 0) {
		if ( _len_signedFT % sizeof(*_tmp_signedFT) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_signedFT = (char*)malloc(_len_signedFT);
		if (_in_signedFT == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_signedFT, _len_signedFT, _tmp_signedFT, _len_signedFT)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_eCMD != NULL && _len_eCMD != 0) {
		if ( _len_eCMD % sizeof(*_tmp_eCMD) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_eCMD = (char*)malloc(_len_eCMD);
		if (_in_eCMD == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_eCMD, _len_eCMD, _tmp_eCMD, _len_eCMD)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_eAESkey != NULL && _len_eAESkey != 0) {
		if ( _len_eAESkey % sizeof(*_tmp_eAESkey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_eAESkey = (char*)malloc(_len_eAESkey);
		if (_in_eAESkey == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_eAESkey, _len_eAESkey, _tmp_eAESkey, _len_eAESkey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_cResponse != NULL && _len_cResponse != 0) {
		if ( _len_cResponse % sizeof(*_tmp_cResponse) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_cResponse = (char*)malloc(_len_cResponse)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_cResponse, 0, _len_cResponse);
	}

	ms->ms_retval = ecall_commandPVRA(_in_sealedstate, _tmp_sealedstate_size, _in_signedFT, _tmp_signedFT_size, _in_eCMD, _tmp_eCMD_size, _in_eAESkey, _tmp_eAESkey_size, _in_cResponse, _tmp_cResponse_size);
	if (_in_cResponse) {
		if (memcpy_s(_tmp_cResponse, _len_cResponse, _in_cResponse, _len_cResponse)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealedstate) free(_in_sealedstate);
	if (_in_signedFT) free(_in_signedFT);
	if (_in_eCMD) free(_in_eCMD);
	if (_in_eAESkey) free(_in_eAESkey);
	if (_in_cResponse) free(_in_cResponse);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_key_gen_and_seal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_key_gen_and_seal_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_key_gen_and_seal_t* ms = SGX_CAST(ms_ecall_key_gen_and_seal_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_pubkey = ms->ms_pubkey;
	size_t _tmp_pubkey_size = ms->ms_pubkey_size;
	size_t _len_pubkey = _tmp_pubkey_size;
	char* _in_pubkey = NULL;
	char* _tmp_sealedprivkey = ms->ms_sealedprivkey;
	size_t _tmp_sealedprivkey_size = ms->ms_sealedprivkey_size;
	size_t _len_sealedprivkey = _tmp_sealedprivkey_size;
	char* _in_sealedprivkey = NULL;

	CHECK_UNIQUE_POINTER(_tmp_pubkey, _len_pubkey);
	CHECK_UNIQUE_POINTER(_tmp_sealedprivkey, _len_sealedprivkey);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_pubkey != NULL && _len_pubkey != 0) {
		if ( _len_pubkey % sizeof(*_tmp_pubkey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_pubkey = (char*)malloc(_len_pubkey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pubkey, 0, _len_pubkey);
	}
	if (_tmp_sealedprivkey != NULL && _len_sealedprivkey != 0) {
		if ( _len_sealedprivkey % sizeof(*_tmp_sealedprivkey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealedprivkey = (char*)malloc(_len_sealedprivkey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealedprivkey, 0, _len_sealedprivkey);
	}

	ms->ms_retval = ecall_key_gen_and_seal(_in_pubkey, _tmp_pubkey_size, _in_sealedprivkey, _tmp_sealedprivkey_size);
	if (_in_pubkey) {
		if (memcpy_s(_tmp_pubkey, _len_pubkey, _in_pubkey, _len_pubkey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_sealedprivkey) {
		if (memcpy_s(_tmp_sealedprivkey, _len_sealedprivkey, _in_sealedprivkey, _len_sealedprivkey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_pubkey) free(_in_pubkey);
	if (_in_sealedprivkey) free(_in_sealedprivkey);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_key_gen_and_seal_all(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_key_gen_and_seal_all_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_key_gen_and_seal_all_t* ms = SGX_CAST(ms_ecall_key_gen_and_seal_all_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_sealedpubkey = ms->ms_sealedpubkey;
	size_t _tmp_sealedpubkey_size = ms->ms_sealedpubkey_size;
	size_t _len_sealedpubkey = _tmp_sealedpubkey_size;
	char* _in_sealedpubkey = NULL;
	char* _tmp_sealedprivkey = ms->ms_sealedprivkey;
	size_t _tmp_sealedprivkey_size = ms->ms_sealedprivkey_size;
	size_t _len_sealedprivkey = _tmp_sealedprivkey_size;
	char* _in_sealedprivkey = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealedpubkey, _len_sealedpubkey);
	CHECK_UNIQUE_POINTER(_tmp_sealedprivkey, _len_sealedprivkey);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealedpubkey != NULL && _len_sealedpubkey != 0) {
		if ( _len_sealedpubkey % sizeof(*_tmp_sealedpubkey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealedpubkey = (char*)malloc(_len_sealedpubkey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealedpubkey, 0, _len_sealedpubkey);
	}
	if (_tmp_sealedprivkey != NULL && _len_sealedprivkey != 0) {
		if ( _len_sealedprivkey % sizeof(*_tmp_sealedprivkey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealedprivkey = (char*)malloc(_len_sealedprivkey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealedprivkey, 0, _len_sealedprivkey);
	}

	ms->ms_retval = ecall_key_gen_and_seal_all(_in_sealedpubkey, _tmp_sealedpubkey_size, _in_sealedprivkey, _tmp_sealedprivkey_size);
	if (_in_sealedpubkey) {
		if (memcpy_s(_tmp_sealedpubkey, _len_sealedpubkey, _in_sealedpubkey, _len_sealedpubkey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_sealedprivkey) {
		if (memcpy_s(_tmp_sealedprivkey, _len_sealedprivkey, _in_sealedprivkey, _len_sealedprivkey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealedpubkey) free(_in_sealedpubkey);
	if (_in_sealedprivkey) free(_in_sealedprivkey);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_key_gen_vsc(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_key_gen_vsc_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_key_gen_vsc_t* ms = SGX_CAST(ms_ecall_key_gen_vsc_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_aes_gcm_key = ms->ms_aes_gcm_key;
	size_t _tmp_aes_gcm_key_size = ms->ms_aes_gcm_key_size;
	size_t _len_aes_gcm_key = _tmp_aes_gcm_key_size;
	uint8_t* _in_aes_gcm_key = NULL;

	CHECK_UNIQUE_POINTER(_tmp_aes_gcm_key, _len_aes_gcm_key);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_aes_gcm_key != NULL && _len_aes_gcm_key != 0) {
		if ( _len_aes_gcm_key % sizeof(*_tmp_aes_gcm_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_aes_gcm_key = (uint8_t*)malloc(_len_aes_gcm_key)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_aes_gcm_key, 0, _len_aes_gcm_key);
	}

	ms->ms_retval = ecall_key_gen_vsc(_in_aes_gcm_key, _tmp_aes_gcm_key_size);
	if (_in_aes_gcm_key) {
		if (memcpy_s(_tmp_aes_gcm_key, _len_aes_gcm_key, _in_aes_gcm_key, _len_aes_gcm_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_aes_gcm_key) free(_in_aes_gcm_key);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_generate_key_ecdsa(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_generate_key_ecdsa_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_generate_key_ecdsa_t* ms = SGX_CAST(ms_ecall_generate_key_ecdsa_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_pub_key_buffer = ms->ms_pub_key_buffer;
	size_t _len_pub_key_buffer = 2048;
	uint8_t* _in_pub_key_buffer = NULL;
	uint8_t* _tmp_priv_key_buffer = ms->ms_priv_key_buffer;
	size_t _len_priv_key_buffer = 2048;
	uint8_t* _in_priv_key_buffer = NULL;

	CHECK_UNIQUE_POINTER(_tmp_pub_key_buffer, _len_pub_key_buffer);
	CHECK_UNIQUE_POINTER(_tmp_priv_key_buffer, _len_priv_key_buffer);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_pub_key_buffer != NULL && _len_pub_key_buffer != 0) {
		if ( _len_pub_key_buffer % sizeof(*_tmp_pub_key_buffer) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_pub_key_buffer = (uint8_t*)malloc(_len_pub_key_buffer)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pub_key_buffer, 0, _len_pub_key_buffer);
	}
	if (_tmp_priv_key_buffer != NULL && _len_priv_key_buffer != 0) {
		if ( _len_priv_key_buffer % sizeof(*_tmp_priv_key_buffer) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_priv_key_buffer = (uint8_t*)malloc(_len_priv_key_buffer)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_priv_key_buffer, 0, _len_priv_key_buffer);
	}

	ms->ms_retval = ecall_generate_key_ecdsa(_in_pub_key_buffer, _in_priv_key_buffer);
	if (_in_pub_key_buffer) {
		if (memcpy_s(_tmp_pub_key_buffer, _len_pub_key_buffer, _in_pub_key_buffer, _len_pub_key_buffer)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_priv_key_buffer) {
		if (memcpy_s(_tmp_priv_key_buffer, _len_priv_key_buffer, _in_priv_key_buffer, _len_priv_key_buffer)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_pub_key_buffer) free(_in_pub_key_buffer);
	if (_in_priv_key_buffer) free(_in_priv_key_buffer);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_encrypt_aes(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_encrypt_aes_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_encrypt_aes_t* ms = SGX_CAST(ms_ecall_encrypt_aes_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_aes_key = ms->ms_aes_key;
	size_t _len_aes_key = 16;
	uint8_t* _in_aes_key = NULL;
	char* _tmp_decMessageIn = ms->ms_decMessageIn;
	size_t _len_decMessageIn = 2048;
	char* _in_decMessageIn = NULL;
	char* _tmp_encMessageOut = ms->ms_encMessageOut;
	size_t _len_encMessageOut = 2048;
	char* _in_encMessageOut = NULL;

	CHECK_UNIQUE_POINTER(_tmp_aes_key, _len_aes_key);
	CHECK_UNIQUE_POINTER(_tmp_decMessageIn, _len_decMessageIn);
	CHECK_UNIQUE_POINTER(_tmp_encMessageOut, _len_encMessageOut);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_aes_key != NULL && _len_aes_key != 0) {
		if ( _len_aes_key % sizeof(*_tmp_aes_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_aes_key = (uint8_t*)malloc(_len_aes_key);
		if (_in_aes_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_aes_key, _len_aes_key, _tmp_aes_key, _len_aes_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_decMessageIn != NULL && _len_decMessageIn != 0) {
		if ( _len_decMessageIn % sizeof(*_tmp_decMessageIn) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_decMessageIn = (char*)malloc(_len_decMessageIn);
		if (_in_decMessageIn == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_decMessageIn, _len_decMessageIn, _tmp_decMessageIn, _len_decMessageIn)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_encMessageOut != NULL && _len_encMessageOut != 0) {
		if ( _len_encMessageOut % sizeof(*_tmp_encMessageOut) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_encMessageOut = (char*)malloc(_len_encMessageOut)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_encMessageOut, 0, _len_encMessageOut);
	}

	ms->ms_retval = ecall_encrypt_aes(_in_aes_key, _in_decMessageIn, ms->ms_lenIn, _in_encMessageOut);
	if (_in_encMessageOut) {
		if (memcpy_s(_tmp_encMessageOut, _len_encMessageOut, _in_encMessageOut, _len_encMessageOut)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_aes_key) free(_in_aes_key);
	if (_in_decMessageIn) free(_in_decMessageIn);
	if (_in_encMessageOut) free(_in_encMessageOut);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_decrypt_aes(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_decrypt_aes_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_decrypt_aes_t* ms = SGX_CAST(ms_ecall_decrypt_aes_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_aes_key = ms->ms_aes_key;
	size_t _len_aes_key = 16;
	uint8_t* _in_aes_key = NULL;
	char* _tmp_encMessageIn = ms->ms_encMessageIn;
	size_t _len_encMessageIn = 2048;
	char* _in_encMessageIn = NULL;
	char* _tmp_decMessageOut = ms->ms_decMessageOut;
	size_t _len_decMessageOut = 2048;
	char* _in_decMessageOut = NULL;

	CHECK_UNIQUE_POINTER(_tmp_aes_key, _len_aes_key);
	CHECK_UNIQUE_POINTER(_tmp_encMessageIn, _len_encMessageIn);
	CHECK_UNIQUE_POINTER(_tmp_decMessageOut, _len_decMessageOut);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_aes_key != NULL && _len_aes_key != 0) {
		if ( _len_aes_key % sizeof(*_tmp_aes_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_aes_key = (uint8_t*)malloc(_len_aes_key);
		if (_in_aes_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_aes_key, _len_aes_key, _tmp_aes_key, _len_aes_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_encMessageIn != NULL && _len_encMessageIn != 0) {
		if ( _len_encMessageIn % sizeof(*_tmp_encMessageIn) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_encMessageIn = (char*)malloc(_len_encMessageIn);
		if (_in_encMessageIn == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_encMessageIn, _len_encMessageIn, _tmp_encMessageIn, _len_encMessageIn)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_decMessageOut != NULL && _len_decMessageOut != 0) {
		if ( _len_decMessageOut % sizeof(*_tmp_decMessageOut) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_decMessageOut = (char*)malloc(_len_decMessageOut)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_decMessageOut, 0, _len_decMessageOut);
	}

	ms->ms_retval = ecall_decrypt_aes(_in_aes_key, _in_encMessageIn, ms->ms_lenIn, _in_decMessageOut);
	if (_in_decMessageOut) {
		if (memcpy_s(_tmp_decMessageOut, _len_decMessageOut, _in_decMessageOut, _len_decMessageOut)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_aes_key) free(_in_aes_key);
	if (_in_encMessageIn) free(_in_encMessageIn);
	if (_in_decMessageOut) free(_in_decMessageOut);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_vsc(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_vsc_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_vsc_t* ms = SGX_CAST(ms_ecall_vsc_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_aes_key = ms->ms_aes_key;
	size_t _len_aes_key = 16;
	uint8_t* _in_aes_key = NULL;
	uint8_t* _tmp_enc_enclave_state_in = ms->ms_enc_enclave_state_in;
	size_t _len_enc_enclave_state_in = 2048;
	uint8_t* _in_enc_enclave_state_in = NULL;
	uint8_t* _tmp_enc_command = ms->ms_enc_command;
	size_t _len_enc_command = 2048;
	uint8_t* _in_enc_command = NULL;
	uint8_t* _tmp_signature = ms->ms_signature;
	size_t _len_signature = 2048;
	uint8_t* _in_signature = NULL;
	uint8_t* _tmp_pub_key_buffer = ms->ms_pub_key_buffer;
	size_t _len_pub_key_buffer = 2048;
	uint8_t* _in_pub_key_buffer = NULL;
	int* _tmp_building_access = ms->ms_building_access;
	size_t _len_building_access = 1 * sizeof(int);
	int* _in_building_access = NULL;
	uint8_t* _tmp_enc_enclave_state_out = ms->ms_enc_enclave_state_out;
	size_t _len_enc_enclave_state_out = 2048;
	uint8_t* _in_enc_enclave_state_out = NULL;

	CHECK_UNIQUE_POINTER(_tmp_aes_key, _len_aes_key);
	CHECK_UNIQUE_POINTER(_tmp_enc_enclave_state_in, _len_enc_enclave_state_in);
	CHECK_UNIQUE_POINTER(_tmp_enc_command, _len_enc_command);
	CHECK_UNIQUE_POINTER(_tmp_signature, _len_signature);
	CHECK_UNIQUE_POINTER(_tmp_pub_key_buffer, _len_pub_key_buffer);
	CHECK_UNIQUE_POINTER(_tmp_building_access, _len_building_access);
	CHECK_UNIQUE_POINTER(_tmp_enc_enclave_state_out, _len_enc_enclave_state_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_aes_key != NULL && _len_aes_key != 0) {
		if ( _len_aes_key % sizeof(*_tmp_aes_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_aes_key = (uint8_t*)malloc(_len_aes_key);
		if (_in_aes_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_aes_key, _len_aes_key, _tmp_aes_key, _len_aes_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_enc_enclave_state_in != NULL && _len_enc_enclave_state_in != 0) {
		if ( _len_enc_enclave_state_in % sizeof(*_tmp_enc_enclave_state_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_enc_enclave_state_in = (uint8_t*)malloc(_len_enc_enclave_state_in);
		if (_in_enc_enclave_state_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_enc_enclave_state_in, _len_enc_enclave_state_in, _tmp_enc_enclave_state_in, _len_enc_enclave_state_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_enc_command != NULL && _len_enc_command != 0) {
		if ( _len_enc_command % sizeof(*_tmp_enc_command) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_enc_command = (uint8_t*)malloc(_len_enc_command);
		if (_in_enc_command == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_enc_command, _len_enc_command, _tmp_enc_command, _len_enc_command)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_signature != NULL && _len_signature != 0) {
		if ( _len_signature % sizeof(*_tmp_signature) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_signature = (uint8_t*)malloc(_len_signature);
		if (_in_signature == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_signature, _len_signature, _tmp_signature, _len_signature)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_pub_key_buffer != NULL && _len_pub_key_buffer != 0) {
		if ( _len_pub_key_buffer % sizeof(*_tmp_pub_key_buffer) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_pub_key_buffer = (uint8_t*)malloc(_len_pub_key_buffer);
		if (_in_pub_key_buffer == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_pub_key_buffer, _len_pub_key_buffer, _tmp_pub_key_buffer, _len_pub_key_buffer)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_building_access != NULL && _len_building_access != 0) {
		if ( _len_building_access % sizeof(*_tmp_building_access) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_building_access = (int*)malloc(_len_building_access)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_building_access, 0, _len_building_access);
	}
	if (_tmp_enc_enclave_state_out != NULL && _len_enc_enclave_state_out != 0) {
		if ( _len_enc_enclave_state_out % sizeof(*_tmp_enc_enclave_state_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_enc_enclave_state_out = (uint8_t*)malloc(_len_enc_enclave_state_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_enc_enclave_state_out, 0, _len_enc_enclave_state_out);
	}

	ms->ms_retval = ecall_vsc(_in_aes_key, _in_enc_enclave_state_in, ms->ms_lenInEncEnclaveState, _in_enc_command, ms->ms_lenInEncCommand, _in_signature, _in_pub_key_buffer, ms->ms_counter, _in_building_access, _in_enc_enclave_state_out);
	if (_in_building_access) {
		if (memcpy_s(_tmp_building_access, _len_building_access, _in_building_access, _len_building_access)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_enc_enclave_state_out) {
		if (memcpy_s(_tmp_enc_enclave_state_out, _len_enc_enclave_state_out, _in_enc_enclave_state_out, _len_enc_enclave_state_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_aes_key) free(_in_aes_key);
	if (_in_enc_enclave_state_in) free(_in_enc_enclave_state_in);
	if (_in_enc_command) free(_in_enc_command);
	if (_in_signature) free(_in_signature);
	if (_in_pub_key_buffer) free(_in_pub_key_buffer);
	if (_in_building_access) free(_in_building_access);
	if (_in_enc_enclave_state_out) free(_in_enc_enclave_state_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_create_client_input_json(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_create_client_input_json_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_create_client_input_json_t* ms = SGX_CAST(ms_ecall_create_client_input_json_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_aes_key = ms->ms_aes_key;
	size_t _len_aes_key = 16;
	uint8_t* _in_aes_key = NULL;
	uint8_t* _tmp_encrypted_client_input_out = ms->ms_encrypted_client_input_out;
	size_t _len_encrypted_client_input_out = 2048;
	uint8_t* _in_encrypted_client_input_out = NULL;

	CHECK_UNIQUE_POINTER(_tmp_aes_key, _len_aes_key);
	CHECK_UNIQUE_POINTER(_tmp_encrypted_client_input_out, _len_encrypted_client_input_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_aes_key != NULL && _len_aes_key != 0) {
		if ( _len_aes_key % sizeof(*_tmp_aes_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_aes_key = (uint8_t*)malloc(_len_aes_key);
		if (_in_aes_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_aes_key, _len_aes_key, _tmp_aes_key, _len_aes_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_encrypted_client_input_out != NULL && _len_encrypted_client_input_out != 0) {
		if ( _len_encrypted_client_input_out % sizeof(*_tmp_encrypted_client_input_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_encrypted_client_input_out = (uint8_t*)malloc(_len_encrypted_client_input_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_encrypted_client_input_out, 0, _len_encrypted_client_input_out);
	}

	ms->ms_retval = ecall_create_client_input_json(_in_aes_key, ms->ms_uuid, ms->ms_command, ms->ms_result, _in_encrypted_client_input_out);
	if (_in_encrypted_client_input_out) {
		if (memcpy_s(_tmp_encrypted_client_input_out, _len_encrypted_client_input_out, _in_encrypted_client_input_out, _len_encrypted_client_input_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_aes_key) free(_in_aes_key);
	if (_in_encrypted_client_input_out) free(_in_encrypted_client_input_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_create_enclave_state_json(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_create_enclave_state_json_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_create_enclave_state_json_t* ms = SGX_CAST(ms_ecall_create_enclave_state_json_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_aes_key = ms->ms_aes_key;
	size_t _len_aes_key = 16;
	uint8_t* _in_aes_key = NULL;
	uint8_t* _tmp_encrypted_enclave_out = ms->ms_encrypted_enclave_out;
	size_t _len_encrypted_enclave_out = 2048;
	uint8_t* _in_encrypted_enclave_out = NULL;

	CHECK_UNIQUE_POINTER(_tmp_aes_key, _len_aes_key);
	CHECK_UNIQUE_POINTER(_tmp_encrypted_enclave_out, _len_encrypted_enclave_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_aes_key != NULL && _len_aes_key != 0) {
		if ( _len_aes_key % sizeof(*_tmp_aes_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_aes_key = (uint8_t*)malloc(_len_aes_key);
		if (_in_aes_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_aes_key, _len_aes_key, _tmp_aes_key, _len_aes_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_encrypted_enclave_out != NULL && _len_encrypted_enclave_out != 0) {
		if ( _len_encrypted_enclave_out % sizeof(*_tmp_encrypted_enclave_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_encrypted_enclave_out = (uint8_t*)malloc(_len_encrypted_enclave_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_encrypted_enclave_out, 0, _len_encrypted_enclave_out);
	}

	ms->ms_retval = ecall_create_enclave_state_json(_in_aes_key, _in_encrypted_enclave_out);
	if (_in_encrypted_enclave_out) {
		if (memcpy_s(_tmp_encrypted_enclave_out, _len_encrypted_enclave_out, _in_encrypted_enclave_out, _len_encrypted_enclave_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_aes_key) free(_in_aes_key);
	if (_in_encrypted_enclave_out) free(_in_encrypted_enclave_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_enclave_state_add_user(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_enclave_state_add_user_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_enclave_state_add_user_t* ms = SGX_CAST(ms_ecall_enclave_state_add_user_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_aes_key = ms->ms_aes_key;
	size_t _len_aes_key = 16;
	uint8_t* _in_aes_key = NULL;
	uint8_t* _tmp_enc_enclave_state_in = ms->ms_enc_enclave_state_in;
	size_t _len_enc_enclave_state_in = 2048;
	uint8_t* _in_enc_enclave_state_in = NULL;
	uint8_t* _tmp_new_enc_enclave_state_out = ms->ms_new_enc_enclave_state_out;
	size_t _len_new_enc_enclave_state_out = 2048;
	uint8_t* _in_new_enc_enclave_state_out = NULL;

	CHECK_UNIQUE_POINTER(_tmp_aes_key, _len_aes_key);
	CHECK_UNIQUE_POINTER(_tmp_enc_enclave_state_in, _len_enc_enclave_state_in);
	CHECK_UNIQUE_POINTER(_tmp_new_enc_enclave_state_out, _len_new_enc_enclave_state_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_aes_key != NULL && _len_aes_key != 0) {
		if ( _len_aes_key % sizeof(*_tmp_aes_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_aes_key = (uint8_t*)malloc(_len_aes_key);
		if (_in_aes_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_aes_key, _len_aes_key, _tmp_aes_key, _len_aes_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_enc_enclave_state_in != NULL && _len_enc_enclave_state_in != 0) {
		if ( _len_enc_enclave_state_in % sizeof(*_tmp_enc_enclave_state_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_enc_enclave_state_in = (uint8_t*)malloc(_len_enc_enclave_state_in);
		if (_in_enc_enclave_state_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_enc_enclave_state_in, _len_enc_enclave_state_in, _tmp_enc_enclave_state_in, _len_enc_enclave_state_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_new_enc_enclave_state_out != NULL && _len_new_enc_enclave_state_out != 0) {
		if ( _len_new_enc_enclave_state_out % sizeof(*_tmp_new_enc_enclave_state_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_new_enc_enclave_state_out = (uint8_t*)malloc(_len_new_enc_enclave_state_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_new_enc_enclave_state_out, 0, _len_new_enc_enclave_state_out);
	}

	ms->ms_retval = ecall_enclave_state_add_user(_in_aes_key, _in_enc_enclave_state_in, ms->ms_lenIn, _in_new_enc_enclave_state_out);
	if (_in_new_enc_enclave_state_out) {
		if (memcpy_s(_tmp_new_enc_enclave_state_out, _len_new_enc_enclave_state_out, _in_new_enc_enclave_state_out, _len_new_enc_enclave_state_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_aes_key) free(_in_aes_key);
	if (_in_enc_enclave_state_in) free(_in_enc_enclave_state_in);
	if (_in_new_enc_enclave_state_out) free(_in_new_enc_enclave_state_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_total_counter(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_total_counter_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_total_counter_t* ms = SGX_CAST(ms_ecall_get_total_counter_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_aes_key = ms->ms_aes_key;
	size_t _len_aes_key = 16;
	uint8_t* _in_aes_key = NULL;
	uint8_t* _tmp_enc_enclave_state_in = ms->ms_enc_enclave_state_in;
	size_t _len_enc_enclave_state_in = 2048;
	uint8_t* _in_enc_enclave_state_in = NULL;
	int* _tmp_total_counter = ms->ms_total_counter;
	size_t _len_total_counter = 1 * sizeof(int);
	int* _in_total_counter = NULL;

	CHECK_UNIQUE_POINTER(_tmp_aes_key, _len_aes_key);
	CHECK_UNIQUE_POINTER(_tmp_enc_enclave_state_in, _len_enc_enclave_state_in);
	CHECK_UNIQUE_POINTER(_tmp_total_counter, _len_total_counter);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_aes_key != NULL && _len_aes_key != 0) {
		if ( _len_aes_key % sizeof(*_tmp_aes_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_aes_key = (uint8_t*)malloc(_len_aes_key);
		if (_in_aes_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_aes_key, _len_aes_key, _tmp_aes_key, _len_aes_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_enc_enclave_state_in != NULL && _len_enc_enclave_state_in != 0) {
		if ( _len_enc_enclave_state_in % sizeof(*_tmp_enc_enclave_state_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_enc_enclave_state_in = (uint8_t*)malloc(_len_enc_enclave_state_in);
		if (_in_enc_enclave_state_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_enc_enclave_state_in, _len_enc_enclave_state_in, _tmp_enc_enclave_state_in, _len_enc_enclave_state_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_total_counter != NULL && _len_total_counter != 0) {
		if ( _len_total_counter % sizeof(*_tmp_total_counter) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_total_counter = (int*)malloc(_len_total_counter)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_total_counter, 0, _len_total_counter);
	}

	ms->ms_retval = ecall_get_total_counter(_in_aes_key, _in_enc_enclave_state_in, ms->ms_lenIn, _in_total_counter);
	if (_in_total_counter) {
		if (memcpy_s(_tmp_total_counter, _len_total_counter, _in_total_counter, _len_total_counter)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_aes_key) free(_in_aes_key);
	if (_in_enc_enclave_state_in) free(_in_enc_enclave_state_in);
	if (_in_total_counter) free(_in_total_counter);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_enclave_state_add_counter_mismatch(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_enclave_state_add_counter_mismatch_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_enclave_state_add_counter_mismatch_t* ms = SGX_CAST(ms_ecall_enclave_state_add_counter_mismatch_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_aes_key = ms->ms_aes_key;
	size_t _len_aes_key = 16;
	uint8_t* _in_aes_key = NULL;
	uint8_t* _tmp_enc_enclave_state_in = ms->ms_enc_enclave_state_in;
	size_t _len_enc_enclave_state_in = 2048;
	uint8_t* _in_enc_enclave_state_in = NULL;
	uint8_t* _tmp_enc_cli_in = ms->ms_enc_cli_in;
	size_t _len_enc_cli_in = 2048;
	uint8_t* _in_enc_cli_in = NULL;
	uint8_t* _tmp_new_enc_enclave_state_out = ms->ms_new_enc_enclave_state_out;
	size_t _len_new_enc_enclave_state_out = 2048;
	uint8_t* _in_new_enc_enclave_state_out = NULL;

	CHECK_UNIQUE_POINTER(_tmp_aes_key, _len_aes_key);
	CHECK_UNIQUE_POINTER(_tmp_enc_enclave_state_in, _len_enc_enclave_state_in);
	CHECK_UNIQUE_POINTER(_tmp_enc_cli_in, _len_enc_cli_in);
	CHECK_UNIQUE_POINTER(_tmp_new_enc_enclave_state_out, _len_new_enc_enclave_state_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_aes_key != NULL && _len_aes_key != 0) {
		if ( _len_aes_key % sizeof(*_tmp_aes_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_aes_key = (uint8_t*)malloc(_len_aes_key);
		if (_in_aes_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_aes_key, _len_aes_key, _tmp_aes_key, _len_aes_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_enc_enclave_state_in != NULL && _len_enc_enclave_state_in != 0) {
		if ( _len_enc_enclave_state_in % sizeof(*_tmp_enc_enclave_state_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_enc_enclave_state_in = (uint8_t*)malloc(_len_enc_enclave_state_in);
		if (_in_enc_enclave_state_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_enc_enclave_state_in, _len_enc_enclave_state_in, _tmp_enc_enclave_state_in, _len_enc_enclave_state_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_enc_cli_in != NULL && _len_enc_cli_in != 0) {
		if ( _len_enc_cli_in % sizeof(*_tmp_enc_cli_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_enc_cli_in = (uint8_t*)malloc(_len_enc_cli_in);
		if (_in_enc_cli_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_enc_cli_in, _len_enc_cli_in, _tmp_enc_cli_in, _len_enc_cli_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_new_enc_enclave_state_out != NULL && _len_new_enc_enclave_state_out != 0) {
		if ( _len_new_enc_enclave_state_out % sizeof(*_tmp_new_enc_enclave_state_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_new_enc_enclave_state_out = (uint8_t*)malloc(_len_new_enc_enclave_state_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_new_enc_enclave_state_out, 0, _len_new_enc_enclave_state_out);
	}

	ms->ms_retval = ecall_enclave_state_add_counter_mismatch(_in_aes_key, ms->ms_delta, _in_enc_enclave_state_in, ms->ms_lenIn, _in_enc_cli_in, ms->ms_lenInCliIn, _in_new_enc_enclave_state_out);
	if (_in_new_enc_enclave_state_out) {
		if (memcpy_s(_tmp_new_enc_enclave_state_out, _len_new_enc_enclave_state_out, _in_new_enc_enclave_state_out, _len_new_enc_enclave_state_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_aes_key) free(_in_aes_key);
	if (_in_enc_enclave_state_in) free(_in_enc_enclave_state_in);
	if (_in_enc_cli_in) free(_in_enc_cli_in);
	if (_in_new_enc_enclave_state_out) free(_in_new_enc_enclave_state_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_enclave_state_status_query(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_enclave_state_status_query_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_enclave_state_status_query_t* ms = SGX_CAST(ms_ecall_enclave_state_status_query_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_aes_key = ms->ms_aes_key;
	size_t _len_aes_key = 16;
	uint8_t* _in_aes_key = NULL;
	uint8_t* _tmp_enc_enclave_state_in = ms->ms_enc_enclave_state_in;
	size_t _len_enc_enclave_state_in = 2048;
	uint8_t* _in_enc_enclave_state_in = NULL;
	int* _tmp_building_access = ms->ms_building_access;
	size_t _len_building_access = 1 * sizeof(int);
	int* _in_building_access = NULL;
	uint8_t* _tmp_new_enc_enclave_state_out = ms->ms_new_enc_enclave_state_out;
	size_t _len_new_enc_enclave_state_out = 2048;
	uint8_t* _in_new_enc_enclave_state_out = NULL;

	CHECK_UNIQUE_POINTER(_tmp_aes_key, _len_aes_key);
	CHECK_UNIQUE_POINTER(_tmp_enc_enclave_state_in, _len_enc_enclave_state_in);
	CHECK_UNIQUE_POINTER(_tmp_building_access, _len_building_access);
	CHECK_UNIQUE_POINTER(_tmp_new_enc_enclave_state_out, _len_new_enc_enclave_state_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_aes_key != NULL && _len_aes_key != 0) {
		if ( _len_aes_key % sizeof(*_tmp_aes_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_aes_key = (uint8_t*)malloc(_len_aes_key);
		if (_in_aes_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_aes_key, _len_aes_key, _tmp_aes_key, _len_aes_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_enc_enclave_state_in != NULL && _len_enc_enclave_state_in != 0) {
		if ( _len_enc_enclave_state_in % sizeof(*_tmp_enc_enclave_state_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_enc_enclave_state_in = (uint8_t*)malloc(_len_enc_enclave_state_in);
		if (_in_enc_enclave_state_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_enc_enclave_state_in, _len_enc_enclave_state_in, _tmp_enc_enclave_state_in, _len_enc_enclave_state_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_building_access != NULL && _len_building_access != 0) {
		if ( _len_building_access % sizeof(*_tmp_building_access) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_building_access = (int*)malloc(_len_building_access)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_building_access, 0, _len_building_access);
	}
	if (_tmp_new_enc_enclave_state_out != NULL && _len_new_enc_enclave_state_out != 0) {
		if ( _len_new_enc_enclave_state_out % sizeof(*_tmp_new_enc_enclave_state_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_new_enc_enclave_state_out = (uint8_t*)malloc(_len_new_enc_enclave_state_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_new_enc_enclave_state_out, 0, _len_new_enc_enclave_state_out);
	}

	ms->ms_retval = ecall_enclave_state_status_query(_in_aes_key, _in_enc_enclave_state_in, ms->ms_lenIn, ms->ms_uuid, _in_building_access, _in_new_enc_enclave_state_out);
	if (_in_building_access) {
		if (memcpy_s(_tmp_building_access, _len_building_access, _in_building_access, _len_building_access)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_new_enc_enclave_state_out) {
		if (memcpy_s(_tmp_new_enc_enclave_state_out, _len_new_enc_enclave_state_out, _in_new_enc_enclave_state_out, _len_new_enc_enclave_state_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_aes_key) free(_in_aes_key);
	if (_in_enc_enclave_state_in) free(_in_enc_enclave_state_in);
	if (_in_building_access) free(_in_building_access);
	if (_in_new_enc_enclave_state_out) free(_in_new_enc_enclave_state_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_enclave_state_status_update(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_enclave_state_status_update_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_enclave_state_status_update_t* ms = SGX_CAST(ms_ecall_enclave_state_status_update_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_aes_key = ms->ms_aes_key;
	size_t _len_aes_key = 16;
	uint8_t* _in_aes_key = NULL;
	uint8_t* _tmp_enc_enclave_state_in = ms->ms_enc_enclave_state_in;
	size_t _len_enc_enclave_state_in = 2048;
	uint8_t* _in_enc_enclave_state_in = NULL;
	uint8_t* _tmp_new_enc_enclave_state_out = ms->ms_new_enc_enclave_state_out;
	size_t _len_new_enc_enclave_state_out = 2048;
	uint8_t* _in_new_enc_enclave_state_out = NULL;

	CHECK_UNIQUE_POINTER(_tmp_aes_key, _len_aes_key);
	CHECK_UNIQUE_POINTER(_tmp_enc_enclave_state_in, _len_enc_enclave_state_in);
	CHECK_UNIQUE_POINTER(_tmp_new_enc_enclave_state_out, _len_new_enc_enclave_state_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_aes_key != NULL && _len_aes_key != 0) {
		if ( _len_aes_key % sizeof(*_tmp_aes_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_aes_key = (uint8_t*)malloc(_len_aes_key);
		if (_in_aes_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_aes_key, _len_aes_key, _tmp_aes_key, _len_aes_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_enc_enclave_state_in != NULL && _len_enc_enclave_state_in != 0) {
		if ( _len_enc_enclave_state_in % sizeof(*_tmp_enc_enclave_state_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_enc_enclave_state_in = (uint8_t*)malloc(_len_enc_enclave_state_in);
		if (_in_enc_enclave_state_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_enc_enclave_state_in, _len_enc_enclave_state_in, _tmp_enc_enclave_state_in, _len_enc_enclave_state_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_new_enc_enclave_state_out != NULL && _len_new_enc_enclave_state_out != 0) {
		if ( _len_new_enc_enclave_state_out % sizeof(*_tmp_new_enc_enclave_state_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_new_enc_enclave_state_out = (uint8_t*)malloc(_len_new_enc_enclave_state_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_new_enc_enclave_state_out, 0, _len_new_enc_enclave_state_out);
	}

	ms->ms_retval = ecall_enclave_state_status_update(_in_aes_key, _in_enc_enclave_state_in, ms->ms_lenIn, ms->ms_uuid, ms->ms_result, _in_new_enc_enclave_state_out);
	if (_in_new_enc_enclave_state_out) {
		if (memcpy_s(_tmp_new_enc_enclave_state_out, _len_new_enc_enclave_state_out, _in_new_enc_enclave_state_out, _len_new_enc_enclave_state_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_aes_key) free(_in_aes_key);
	if (_in_enc_enclave_state_in) free(_in_enc_enclave_state_in);
	if (_in_new_enc_enclave_state_out) free(_in_new_enc_enclave_state_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_hash_enclave_state_and_command(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_hash_enclave_state_and_command_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_hash_enclave_state_and_command_t* ms = SGX_CAST(ms_ecall_hash_enclave_state_and_command_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_enclave_state_in = ms->ms_enclave_state_in;
	size_t _len_enclave_state_in = 2048;
	uint8_t* _in_enclave_state_in = NULL;
	uint8_t* _tmp_cli_in = ms->ms_cli_in;
	size_t _len_cli_in = 2048;
	uint8_t* _in_cli_in = NULL;
	uint8_t* _tmp_hash = ms->ms_hash;
	size_t _len_hash = 32 * sizeof(uint8_t);
	uint8_t* _in_hash = NULL;

	CHECK_UNIQUE_POINTER(_tmp_enclave_state_in, _len_enclave_state_in);
	CHECK_UNIQUE_POINTER(_tmp_cli_in, _len_cli_in);
	CHECK_UNIQUE_POINTER(_tmp_hash, _len_hash);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_enclave_state_in != NULL && _len_enclave_state_in != 0) {
		if ( _len_enclave_state_in % sizeof(*_tmp_enclave_state_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_enclave_state_in = (uint8_t*)malloc(_len_enclave_state_in);
		if (_in_enclave_state_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_enclave_state_in, _len_enclave_state_in, _tmp_enclave_state_in, _len_enclave_state_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_cli_in != NULL && _len_cli_in != 0) {
		if ( _len_cli_in % sizeof(*_tmp_cli_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_cli_in = (uint8_t*)malloc(_len_cli_in);
		if (_in_cli_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_cli_in, _len_cli_in, _tmp_cli_in, _len_cli_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_hash != NULL && _len_hash != 0) {
		if ( _len_hash % sizeof(*_tmp_hash) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_hash = (uint8_t*)malloc(_len_hash)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_hash, 0, _len_hash);
	}

	ms->ms_retval = ecall_hash_enclave_state_and_command(_in_enclave_state_in, ms->ms_lenInEnclaveState, _in_cli_in, ms->ms_lenInCliIn, _in_hash);
	if (_in_hash) {
		if (memcpy_s(_tmp_hash, _len_hash, _in_hash, _len_hash)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_enclave_state_in) free(_in_enclave_state_in);
	if (_in_cli_in) free(_in_cli_in);
	if (_in_hash) free(_in_hash);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_mbed_sign_enclave_state_and_command_signature(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_mbed_sign_enclave_state_and_command_signature_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_mbed_sign_enclave_state_and_command_signature_t* ms = SGX_CAST(ms_ecall_mbed_sign_enclave_state_and_command_signature_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_enclave_state_in = ms->ms_enclave_state_in;
	size_t _len_enclave_state_in = 2048;
	uint8_t* _in_enclave_state_in = NULL;
	uint8_t* _tmp_cli_in = ms->ms_cli_in;
	size_t _len_cli_in = 2048;
	uint8_t* _in_cli_in = NULL;
	uint8_t* _tmp_priv_key_buffer = ms->ms_priv_key_buffer;
	size_t _len_priv_key_buffer = 2049;
	uint8_t* _in_priv_key_buffer = NULL;
	uint8_t* _tmp_pub_key_buffer = ms->ms_pub_key_buffer;
	size_t _len_pub_key_buffer = 2049;
	uint8_t* _in_pub_key_buffer = NULL;
	uint8_t* _tmp_signature = ms->ms_signature;
	size_t _len_signature = 1024;
	uint8_t* _in_signature = NULL;

	CHECK_UNIQUE_POINTER(_tmp_enclave_state_in, _len_enclave_state_in);
	CHECK_UNIQUE_POINTER(_tmp_cli_in, _len_cli_in);
	CHECK_UNIQUE_POINTER(_tmp_priv_key_buffer, _len_priv_key_buffer);
	CHECK_UNIQUE_POINTER(_tmp_pub_key_buffer, _len_pub_key_buffer);
	CHECK_UNIQUE_POINTER(_tmp_signature, _len_signature);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_enclave_state_in != NULL && _len_enclave_state_in != 0) {
		if ( _len_enclave_state_in % sizeof(*_tmp_enclave_state_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_enclave_state_in = (uint8_t*)malloc(_len_enclave_state_in);
		if (_in_enclave_state_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_enclave_state_in, _len_enclave_state_in, _tmp_enclave_state_in, _len_enclave_state_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_cli_in != NULL && _len_cli_in != 0) {
		if ( _len_cli_in % sizeof(*_tmp_cli_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_cli_in = (uint8_t*)malloc(_len_cli_in);
		if (_in_cli_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_cli_in, _len_cli_in, _tmp_cli_in, _len_cli_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_priv_key_buffer != NULL && _len_priv_key_buffer != 0) {
		if ( _len_priv_key_buffer % sizeof(*_tmp_priv_key_buffer) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_priv_key_buffer = (uint8_t*)malloc(_len_priv_key_buffer)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_priv_key_buffer, 0, _len_priv_key_buffer);
	}
	if (_tmp_pub_key_buffer != NULL && _len_pub_key_buffer != 0) {
		if ( _len_pub_key_buffer % sizeof(*_tmp_pub_key_buffer) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_pub_key_buffer = (uint8_t*)malloc(_len_pub_key_buffer)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pub_key_buffer, 0, _len_pub_key_buffer);
	}
	if (_tmp_signature != NULL && _len_signature != 0) {
		if ( _len_signature % sizeof(*_tmp_signature) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_signature = (uint8_t*)malloc(_len_signature)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_signature, 0, _len_signature);
	}

	ms->ms_retval = ecall_mbed_sign_enclave_state_and_command_signature(_in_enclave_state_in, ms->ms_lenInEnclaveState, _in_cli_in, ms->ms_lenInCliIn, ms->ms_counter, _in_priv_key_buffer, _in_pub_key_buffer, _in_signature);
	if (_in_priv_key_buffer) {
		if (memcpy_s(_tmp_priv_key_buffer, _len_priv_key_buffer, _in_priv_key_buffer, _len_priv_key_buffer)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_pub_key_buffer) {
		if (memcpy_s(_tmp_pub_key_buffer, _len_pub_key_buffer, _in_pub_key_buffer, _len_pub_key_buffer)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_signature) {
		if (memcpy_s(_tmp_signature, _len_signature, _in_signature, _len_signature)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_enclave_state_in) free(_in_enclave_state_in);
	if (_in_cli_in) free(_in_cli_in);
	if (_in_priv_key_buffer) free(_in_priv_key_buffer);
	if (_in_pub_key_buffer) free(_in_pub_key_buffer);
	if (_in_signature) free(_in_signature);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_mbed_verify_enclave_state_and_command_signature(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_mbed_verify_enclave_state_and_command_signature_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_mbed_verify_enclave_state_and_command_signature_t* ms = SGX_CAST(ms_ecall_mbed_verify_enclave_state_and_command_signature_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_enclave_state_in = ms->ms_enclave_state_in;
	size_t _len_enclave_state_in = 2048;
	uint8_t* _in_enclave_state_in = NULL;
	uint8_t* _tmp_cli_in = ms->ms_cli_in;
	size_t _len_cli_in = 2048;
	uint8_t* _in_cli_in = NULL;
	uint8_t* _tmp_public_key_buffer = ms->ms_public_key_buffer;
	size_t _len_public_key_buffer = 2048;
	uint8_t* _in_public_key_buffer = NULL;
	uint8_t* _tmp_signature = ms->ms_signature;
	size_t _len_signature = 1024;
	uint8_t* _in_signature = NULL;

	CHECK_UNIQUE_POINTER(_tmp_enclave_state_in, _len_enclave_state_in);
	CHECK_UNIQUE_POINTER(_tmp_cli_in, _len_cli_in);
	CHECK_UNIQUE_POINTER(_tmp_public_key_buffer, _len_public_key_buffer);
	CHECK_UNIQUE_POINTER(_tmp_signature, _len_signature);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_enclave_state_in != NULL && _len_enclave_state_in != 0) {
		if ( _len_enclave_state_in % sizeof(*_tmp_enclave_state_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_enclave_state_in = (uint8_t*)malloc(_len_enclave_state_in);
		if (_in_enclave_state_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_enclave_state_in, _len_enclave_state_in, _tmp_enclave_state_in, _len_enclave_state_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_cli_in != NULL && _len_cli_in != 0) {
		if ( _len_cli_in % sizeof(*_tmp_cli_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_cli_in = (uint8_t*)malloc(_len_cli_in);
		if (_in_cli_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_cli_in, _len_cli_in, _tmp_cli_in, _len_cli_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_public_key_buffer != NULL && _len_public_key_buffer != 0) {
		if ( _len_public_key_buffer % sizeof(*_tmp_public_key_buffer) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_public_key_buffer = (uint8_t*)malloc(_len_public_key_buffer);
		if (_in_public_key_buffer == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_public_key_buffer, _len_public_key_buffer, _tmp_public_key_buffer, _len_public_key_buffer)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_signature != NULL && _len_signature != 0) {
		if ( _len_signature % sizeof(*_tmp_signature) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_signature = (uint8_t*)malloc(_len_signature);
		if (_in_signature == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_signature, _len_signature, _tmp_signature, _len_signature)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ecall_mbed_verify_enclave_state_and_command_signature(_in_enclave_state_in, ms->ms_lenInEnclaveState, _in_cli_in, ms->ms_lenInCliIn, ms->ms_counter, _in_public_key_buffer, _in_signature);

err:
	if (_in_enclave_state_in) free(_in_enclave_state_in);
	if (_in_cli_in) free(_in_cli_in);
	if (_in_public_key_buffer) free(_in_public_key_buffer);
	if (_in_signature) free(_in_signature);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_verify_enclave_state_and_command_signature(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_verify_enclave_state_and_command_signature_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_verify_enclave_state_and_command_signature_t* ms = SGX_CAST(ms_ecall_verify_enclave_state_and_command_signature_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_enclave_state_in = ms->ms_enclave_state_in;
	size_t _len_enclave_state_in = 2048;
	uint8_t* _in_enclave_state_in = NULL;
	uint8_t* _tmp_cli_in = ms->ms_cli_in;
	size_t _len_cli_in = 2048;
	uint8_t* _in_cli_in = NULL;
	uint8_t* _tmp_private_key_buffer = ms->ms_private_key_buffer;
	size_t _len_private_key_buffer = 2048;
	uint8_t* _in_private_key_buffer = NULL;
	uint8_t* _tmp_signature = ms->ms_signature;
	size_t _len_signature = 2048;
	uint8_t* _in_signature = NULL;
	uint8_t* _tmp_result = ms->ms_result;
	size_t _len_result = 2048;
	uint8_t* _in_result = NULL;

	CHECK_UNIQUE_POINTER(_tmp_enclave_state_in, _len_enclave_state_in);
	CHECK_UNIQUE_POINTER(_tmp_cli_in, _len_cli_in);
	CHECK_UNIQUE_POINTER(_tmp_private_key_buffer, _len_private_key_buffer);
	CHECK_UNIQUE_POINTER(_tmp_signature, _len_signature);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_enclave_state_in != NULL && _len_enclave_state_in != 0) {
		if ( _len_enclave_state_in % sizeof(*_tmp_enclave_state_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_enclave_state_in = (uint8_t*)malloc(_len_enclave_state_in);
		if (_in_enclave_state_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_enclave_state_in, _len_enclave_state_in, _tmp_enclave_state_in, _len_enclave_state_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_cli_in != NULL && _len_cli_in != 0) {
		if ( _len_cli_in % sizeof(*_tmp_cli_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_cli_in = (uint8_t*)malloc(_len_cli_in);
		if (_in_cli_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_cli_in, _len_cli_in, _tmp_cli_in, _len_cli_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_private_key_buffer != NULL && _len_private_key_buffer != 0) {
		if ( _len_private_key_buffer % sizeof(*_tmp_private_key_buffer) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_private_key_buffer = (uint8_t*)malloc(_len_private_key_buffer);
		if (_in_private_key_buffer == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_private_key_buffer, _len_private_key_buffer, _tmp_private_key_buffer, _len_private_key_buffer)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_signature != NULL && _len_signature != 0) {
		if ( _len_signature % sizeof(*_tmp_signature) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_signature = (uint8_t*)malloc(_len_signature);
		if (_in_signature == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_signature, _len_signature, _tmp_signature, _len_signature)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (uint8_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}

	ms->ms_retval = ecall_verify_enclave_state_and_command_signature(_in_enclave_state_in, ms->ms_lenInEnclaveState, _in_cli_in, ms->ms_lenInCliIn, ms->ms_counter, _in_private_key_buffer, _in_signature, _in_result);
	if (_in_result) {
		if (memcpy_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_enclave_state_in) free(_in_enclave_state_in);
	if (_in_cli_in) free(_in_cli_in);
	if (_in_private_key_buffer) free(_in_private_key_buffer);
	if (_in_signature) free(_in_signature);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sign_enclave_state_and_command(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sign_enclave_state_and_command_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sign_enclave_state_and_command_t* ms = SGX_CAST(ms_ecall_sign_enclave_state_and_command_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_enclave_state_in = ms->ms_enclave_state_in;
	size_t _len_enclave_state_in = 2048;
	uint8_t* _in_enclave_state_in = NULL;
	uint8_t* _tmp_cli_in = ms->ms_cli_in;
	size_t _len_cli_in = 2048;
	uint8_t* _in_cli_in = NULL;
	uint8_t* _tmp_private_key_buffer = ms->ms_private_key_buffer;
	size_t _len_private_key_buffer = 2048;
	uint8_t* _in_private_key_buffer = NULL;
	uint8_t* _tmp_signature = ms->ms_signature;
	size_t _len_signature = 2048;
	uint8_t* _in_signature = NULL;

	CHECK_UNIQUE_POINTER(_tmp_enclave_state_in, _len_enclave_state_in);
	CHECK_UNIQUE_POINTER(_tmp_cli_in, _len_cli_in);
	CHECK_UNIQUE_POINTER(_tmp_private_key_buffer, _len_private_key_buffer);
	CHECK_UNIQUE_POINTER(_tmp_signature, _len_signature);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_enclave_state_in != NULL && _len_enclave_state_in != 0) {
		if ( _len_enclave_state_in % sizeof(*_tmp_enclave_state_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_enclave_state_in = (uint8_t*)malloc(_len_enclave_state_in);
		if (_in_enclave_state_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_enclave_state_in, _len_enclave_state_in, _tmp_enclave_state_in, _len_enclave_state_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_cli_in != NULL && _len_cli_in != 0) {
		if ( _len_cli_in % sizeof(*_tmp_cli_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_cli_in = (uint8_t*)malloc(_len_cli_in);
		if (_in_cli_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_cli_in, _len_cli_in, _tmp_cli_in, _len_cli_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_private_key_buffer != NULL && _len_private_key_buffer != 0) {
		if ( _len_private_key_buffer % sizeof(*_tmp_private_key_buffer) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_private_key_buffer = (uint8_t*)malloc(_len_private_key_buffer);
		if (_in_private_key_buffer == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_private_key_buffer, _len_private_key_buffer, _tmp_private_key_buffer, _len_private_key_buffer)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_signature != NULL && _len_signature != 0) {
		if ( _len_signature % sizeof(*_tmp_signature) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_signature = (uint8_t*)malloc(_len_signature)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_signature, 0, _len_signature);
	}

	ms->ms_retval = ecall_sign_enclave_state_and_command(_in_enclave_state_in, ms->ms_lenInEnclaveState, _in_cli_in, ms->ms_lenInCliIn, ms->ms_counter, _in_private_key_buffer, _in_signature);
	if (_in_signature) {
		if (memcpy_s(_tmp_signature, _len_signature, _in_signature, _len_signature)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_enclave_state_in) free(_in_enclave_state_in);
	if (_in_cli_in) free(_in_cli_in);
	if (_in_private_key_buffer) free(_in_private_key_buffer);
	if (_in_signature) free(_in_signature);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_calc_buffer_sizes(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_calc_buffer_sizes_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_calc_buffer_sizes_t* ms = SGX_CAST(ms_ecall_calc_buffer_sizes_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	size_t* _tmp_epubkey_size = ms->ms_epubkey_size;
	size_t _len_epubkey_size = sizeof(size_t);
	size_t* _in_epubkey_size = NULL;
	size_t* _tmp_esealedpubkey_size = ms->ms_esealedpubkey_size;
	size_t _len_esealedpubkey_size = sizeof(size_t);
	size_t* _in_esealedpubkey_size = NULL;
	size_t* _tmp_esealedprivkey_size = ms->ms_esealedprivkey_size;
	size_t _len_esealedprivkey_size = sizeof(size_t);
	size_t* _in_esealedprivkey_size = NULL;
	size_t* _tmp_esignature_size = ms->ms_esignature_size;
	size_t _len_esignature_size = sizeof(size_t);
	size_t* _in_esignature_size = NULL;

	CHECK_UNIQUE_POINTER(_tmp_epubkey_size, _len_epubkey_size);
	CHECK_UNIQUE_POINTER(_tmp_esealedpubkey_size, _len_esealedpubkey_size);
	CHECK_UNIQUE_POINTER(_tmp_esealedprivkey_size, _len_esealedprivkey_size);
	CHECK_UNIQUE_POINTER(_tmp_esignature_size, _len_esignature_size);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_epubkey_size != NULL && _len_epubkey_size != 0) {
		if ( _len_epubkey_size % sizeof(*_tmp_epubkey_size) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_epubkey_size = (size_t*)malloc(_len_epubkey_size)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_epubkey_size, 0, _len_epubkey_size);
	}
	if (_tmp_esealedpubkey_size != NULL && _len_esealedpubkey_size != 0) {
		if ( _len_esealedpubkey_size % sizeof(*_tmp_esealedpubkey_size) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_esealedpubkey_size = (size_t*)malloc(_len_esealedpubkey_size)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_esealedpubkey_size, 0, _len_esealedpubkey_size);
	}
	if (_tmp_esealedprivkey_size != NULL && _len_esealedprivkey_size != 0) {
		if ( _len_esealedprivkey_size % sizeof(*_tmp_esealedprivkey_size) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_esealedprivkey_size = (size_t*)malloc(_len_esealedprivkey_size)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_esealedprivkey_size, 0, _len_esealedprivkey_size);
	}
	if (_tmp_esignature_size != NULL && _len_esignature_size != 0) {
		if ( _len_esignature_size % sizeof(*_tmp_esignature_size) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_esignature_size = (size_t*)malloc(_len_esignature_size)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_esignature_size, 0, _len_esignature_size);
	}

	ms->ms_retval = ecall_calc_buffer_sizes(_in_epubkey_size, _in_esealedpubkey_size, _in_esealedprivkey_size, _in_esignature_size);
	if (_in_epubkey_size) {
		if (memcpy_s(_tmp_epubkey_size, _len_epubkey_size, _in_epubkey_size, _len_epubkey_size)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_esealedpubkey_size) {
		if (memcpy_s(_tmp_esealedpubkey_size, _len_esealedpubkey_size, _in_esealedpubkey_size, _len_esealedpubkey_size)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_esealedprivkey_size) {
		if (memcpy_s(_tmp_esealedprivkey_size, _len_esealedprivkey_size, _in_esealedprivkey_size, _len_esealedprivkey_size)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_esignature_size) {
		if (memcpy_s(_tmp_esignature_size, _len_esignature_size, _in_esignature_size, _len_esignature_size)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_epubkey_size) free(_in_epubkey_size);
	if (_in_esealedpubkey_size) free(_in_esealedpubkey_size);
	if (_in_esealedprivkey_size) free(_in_esealedprivkey_size);
	if (_in_esignature_size) free(_in_esignature_size);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_unseal_and_sign(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_unseal_and_sign_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_unseal_and_sign_t* ms = SGX_CAST(ms_ecall_unseal_and_sign_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_msg = ms->ms_msg;
	uint32_t _tmp_msg_size = ms->ms_msg_size;
	size_t _len_msg = _tmp_msg_size;
	uint8_t* _in_msg = NULL;
	char* _tmp_sealed = ms->ms_sealed;
	size_t _tmp_sealed_size = ms->ms_sealed_size;
	size_t _len_sealed = _tmp_sealed_size;
	char* _in_sealed = NULL;
	char* _tmp_signature = ms->ms_signature;
	size_t _tmp_signature_size = ms->ms_signature_size;
	size_t _len_signature = _tmp_signature_size;
	char* _in_signature = NULL;

	CHECK_UNIQUE_POINTER(_tmp_msg, _len_msg);
	CHECK_UNIQUE_POINTER(_tmp_sealed, _len_sealed);
	CHECK_UNIQUE_POINTER(_tmp_signature, _len_signature);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_msg != NULL && _len_msg != 0) {
		if ( _len_msg % sizeof(*_tmp_msg) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_msg = (uint8_t*)malloc(_len_msg);
		if (_in_msg == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_msg, _len_msg, _tmp_msg, _len_msg)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sealed != NULL && _len_sealed != 0) {
		if ( _len_sealed % sizeof(*_tmp_sealed) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed = (char*)malloc(_len_sealed);
		if (_in_sealed == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed, _len_sealed, _tmp_sealed, _len_sealed)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_signature != NULL && _len_signature != 0) {
		if ( _len_signature % sizeof(*_tmp_signature) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_signature = (char*)malloc(_len_signature)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_signature, 0, _len_signature);
	}

	ms->ms_retval = ecall_unseal_and_sign(_in_msg, _tmp_msg_size, _in_sealed, _tmp_sealed_size, _in_signature, _tmp_signature_size);
	if (_in_signature) {
		if (memcpy_s(_tmp_signature, _len_signature, _in_signature, _len_signature)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_msg) free(_in_msg);
	if (_in_sealed) free(_in_sealed);
	if (_in_signature) free(_in_signature);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_unseal_and_quote(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_unseal_and_quote_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_unseal_and_quote_t* ms = SGX_CAST(ms_ecall_unseal_and_quote_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_report = ms->ms_report;
	size_t _len_report = sizeof(sgx_report_t);
	sgx_report_t* _in_report = NULL;
	sgx_target_info_t* _tmp_target_info = ms->ms_target_info;
	size_t _len_target_info = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_target_info = NULL;
	char* _tmp_sealed = ms->ms_sealed;
	size_t _tmp_sealed_size = ms->ms_sealed_size;
	size_t _len_sealed = _tmp_sealed_size;
	char* _in_sealed = NULL;
	char* _tmp_public_key = ms->ms_public_key;
	size_t _tmp_public_key_size = ms->ms_public_key_size;
	size_t _len_public_key = _tmp_public_key_size;
	char* _in_public_key = NULL;

	CHECK_UNIQUE_POINTER(_tmp_report, _len_report);
	CHECK_UNIQUE_POINTER(_tmp_target_info, _len_target_info);
	CHECK_UNIQUE_POINTER(_tmp_sealed, _len_sealed);
	CHECK_UNIQUE_POINTER(_tmp_public_key, _len_public_key);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_report != NULL && _len_report != 0) {
		if ((_in_report = (sgx_report_t*)malloc(_len_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_report, 0, _len_report);
	}
	if (_tmp_target_info != NULL && _len_target_info != 0) {
		_in_target_info = (sgx_target_info_t*)malloc(_len_target_info);
		if (_in_target_info == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_target_info, _len_target_info, _tmp_target_info, _len_target_info)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sealed != NULL && _len_sealed != 0) {
		if ( _len_sealed % sizeof(*_tmp_sealed) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed = (char*)malloc(_len_sealed);
		if (_in_sealed == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed, _len_sealed, _tmp_sealed, _len_sealed)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_public_key != NULL && _len_public_key != 0) {
		if ( _len_public_key % sizeof(*_tmp_public_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_public_key = (char*)malloc(_len_public_key)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_public_key, 0, _len_public_key);
	}

	ms->ms_retval = ecall_unseal_and_quote(_in_report, _in_target_info, _in_sealed, _tmp_sealed_size, _in_public_key, _tmp_public_key_size);
	if (_in_report) {
		if (memcpy_s(_tmp_report, _len_report, _in_report, _len_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_public_key) {
		if (memcpy_s(_tmp_public_key, _len_public_key, _in_public_key, _len_public_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_report) free(_in_report);
	if (_in_target_info) free(_in_target_info);
	if (_in_sealed) free(_in_sealed);
	if (_in_public_key) free(_in_public_key);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_report_gen(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_report_gen_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_report_gen_t* ms = SGX_CAST(ms_ecall_report_gen_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_report = ms->ms_report;
	size_t _len_report = sizeof(sgx_report_t);
	sgx_report_t* _in_report = NULL;
	sgx_target_info_t* _tmp_target_info = ms->ms_target_info;
	size_t _len_target_info = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_target_info = NULL;

	CHECK_UNIQUE_POINTER(_tmp_report, _len_report);
	CHECK_UNIQUE_POINTER(_tmp_target_info, _len_target_info);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_report != NULL && _len_report != 0) {
		if ((_in_report = (sgx_report_t*)malloc(_len_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_report, 0, _len_report);
	}
	if (_tmp_target_info != NULL && _len_target_info != 0) {
		_in_target_info = (sgx_target_info_t*)malloc(_len_target_info);
		if (_in_target_info == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_target_info, _len_target_info, _tmp_target_info, _len_target_info)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ecall_report_gen(_in_report, _in_target_info, ms->ms_report_data);
	if (_in_report) {
		if (memcpy_s(_tmp_report, _len_report, _in_report, _len_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_report) free(_in_report);
	if (_in_target_info) free(_in_target_info);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[25];
} g_ecall_table = {
	25,
	{
		{(void*)(uintptr_t)sgx_ecall_initPVRA, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_commandPVRA, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_key_gen_and_seal, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_key_gen_and_seal_all, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_key_gen_vsc, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_generate_key_ecdsa, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_encrypt_aes, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_decrypt_aes, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_vsc, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_create_client_input_json, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_create_enclave_state_json, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_enclave_state_add_user, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_total_counter, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_enclave_state_add_counter_mismatch, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_enclave_state_status_query, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_enclave_state_status_update, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_hash_enclave_state_and_command, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_mbed_sign_enclave_state_and_command_signature, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_mbed_verify_enclave_state_and_command_signature, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_verify_enclave_state_and_command_signature, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_sign_enclave_state_and_command, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_calc_buffer_sizes, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_unseal_and_sign, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_unseal_and_quote, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_report_gen, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][25];
} g_dyn_entry_table = {
	2,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_rdtsc(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(1, NULL);

	return status;
}
