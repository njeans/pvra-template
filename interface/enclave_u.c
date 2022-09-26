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

typedef struct ms_ecall_calc_buffer_sizes_t {
	sgx_status_t ms_retval;
	size_t* ms_esignature_size;
} ms_ecall_calc_buffer_sizes_t;

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

sgx_status_t ecall_calc_buffer_sizes(sgx_enclave_id_t eid, sgx_status_t* retval, size_t* esignature_size)
{
	sgx_status_t status;
	ms_ecall_calc_buffer_sizes_t ms;
	ms.ms_esignature_size = esignature_size;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

