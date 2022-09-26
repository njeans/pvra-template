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
	char* _tmp_FT = ms->ms_FT;
	size_t _tmp_FT_size = ms->ms_FT_size;
	size_t _len_FT = _tmp_FT_size;
	char* _in_FT = NULL;
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
	char* _tmp_cRsig = ms->ms_cRsig;
	size_t _tmp_cRsig_size = ms->ms_cRsig_size;
	size_t _len_cRsig = _tmp_cRsig_size;
	char* _in_cRsig = NULL;
	char* _tmp_sealedout = ms->ms_sealedout;
	size_t _tmp_sealedout_size = ms->ms_sealedout_size;
	size_t _len_sealedout = _tmp_sealedout_size;
	char* _in_sealedout = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealedstate, _len_sealedstate);
	CHECK_UNIQUE_POINTER(_tmp_signedFT, _len_signedFT);
	CHECK_UNIQUE_POINTER(_tmp_FT, _len_FT);
	CHECK_UNIQUE_POINTER(_tmp_eCMD, _len_eCMD);
	CHECK_UNIQUE_POINTER(_tmp_eAESkey, _len_eAESkey);
	CHECK_UNIQUE_POINTER(_tmp_cResponse, _len_cResponse);
	CHECK_UNIQUE_POINTER(_tmp_cRsig, _len_cRsig);
	CHECK_UNIQUE_POINTER(_tmp_sealedout, _len_sealedout);

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
	if (_tmp_FT != NULL && _len_FT != 0) {
		if ( _len_FT % sizeof(*_tmp_FT) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_FT = (char*)malloc(_len_FT);
		if (_in_FT == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_FT, _len_FT, _tmp_FT, _len_FT)) {
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
	if (_tmp_cRsig != NULL && _len_cRsig != 0) {
		if ( _len_cRsig % sizeof(*_tmp_cRsig) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_cRsig = (char*)malloc(_len_cRsig)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_cRsig, 0, _len_cRsig);
	}
	if (_tmp_sealedout != NULL && _len_sealedout != 0) {
		if ( _len_sealedout % sizeof(*_tmp_sealedout) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealedout = (char*)malloc(_len_sealedout)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealedout, 0, _len_sealedout);
	}

	ms->ms_retval = ecall_commandPVRA(_in_sealedstate, _tmp_sealedstate_size, _in_signedFT, _tmp_signedFT_size, _in_FT, _tmp_FT_size, _in_eCMD, _tmp_eCMD_size, _in_eAESkey, _tmp_eAESkey_size, _in_cResponse, _tmp_cResponse_size, _in_cRsig, _tmp_cRsig_size, _in_sealedout, _tmp_sealedout_size);
	if (_in_cResponse) {
		if (memcpy_s(_tmp_cResponse, _len_cResponse, _in_cResponse, _len_cResponse)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_cRsig) {
		if (memcpy_s(_tmp_cRsig, _len_cRsig, _in_cRsig, _len_cRsig)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_sealedout) {
		if (memcpy_s(_tmp_sealedout, _len_sealedout, _in_sealedout, _len_sealedout)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealedstate) free(_in_sealedstate);
	if (_in_signedFT) free(_in_signedFT);
	if (_in_FT) free(_in_FT);
	if (_in_eCMD) free(_in_eCMD);
	if (_in_eAESkey) free(_in_eAESkey);
	if (_in_cResponse) free(_in_cResponse);
	if (_in_cRsig) free(_in_cRsig);
	if (_in_sealedout) free(_in_sealedout);
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
	size_t* _tmp_esignature_size = ms->ms_esignature_size;
	size_t _len_esignature_size = sizeof(size_t);
	size_t* _in_esignature_size = NULL;

	CHECK_UNIQUE_POINTER(_tmp_esignature_size, _len_esignature_size);

	//
	// fence after pointer checks
	//
	sgx_lfence();

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

	ms->ms_retval = ecall_calc_buffer_sizes(_in_esignature_size);
	if (_in_esignature_size) {
		if (memcpy_s(_tmp_esignature_size, _len_esignature_size, _in_esignature_size, _len_esignature_size)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_esignature_size) free(_in_esignature_size);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_ecall_initPVRA, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_commandPVRA, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_calc_buffer_sizes, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[3][3];
} g_dyn_entry_table = {
	3,
	{
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
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
sgx_status_t SGX_CDECL ocallbuf(int size)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocallbuf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocallbuf_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocallbuf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocallbuf_t));
	ocalloc_size -= sizeof(ms_ocallbuf_t);

	ms->ms_size = size;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

