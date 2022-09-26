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
sgx_status_t ecall_commandPVRA(char* sealedstate, size_t sealedstate_size, char* signedFT, size_t signedFT_size, char* FT, size_t FT_size, char* eCMD, size_t eCMD_size, char* eAESkey, size_t eAESkey_size, char* cResponse, size_t cResponse_size, char* cRsig, size_t cRsig_size, char* sealedout, size_t sealedout_size);
sgx_status_t ecall_calc_buffer_sizes(size_t* epubkey_size, size_t* esealedpubkey_size, size_t* esealedprivkey_size, size_t* esignature_size);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_rdtsc(void);
sgx_status_t SGX_CDECL ocallbuf(int size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
