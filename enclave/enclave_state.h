#include <sgx_tseal.h>
#include <enclave_t.h>
#include <secp256k1.h>

#include "constants.h"
#include "appPVRA.h"

#ifndef __ENCLAVESTATE_H_
#define __ENCLAVESTATE_H_


struct EK
{
	secp256k1_pubkey sig_pubkey;
	secp256k1_prikey sig_prikey;
	secp256k1_pubkey enc_pubkey;
	secp256k1_prikey enc_prikey;
};

struct SCS
{
	char freshness_tag[HASH_SIZE];
};

struct AR
{
	uint64_t *seqno;
};

typedef uint8_t pubkey_t[64];

struct UK
{
	pubkey_t admin_pubkey;
	pubkey_t * user_pubkeys;
};

struct audit_entry_t {
	packed_address_t user_address;
	uint8_t command_hash[HASH_SIZE];
	uint64_t seqNo;
};

struct AL
{
	uint64_t audit_num;
	size_t num_entries;
	struct audit_entry_t * entries;
};

struct ES
{
	uint64_t num_users;
	struct EK enclavekeys;
	struct SCS counter;
	struct AR antireplay;
	struct AD appdata;
	struct UK publickeys;
	struct AL auditlog;
};

typedef uint32_t cType;

struct private_command {
	cType CT;
	struct cInputs CI;
};

struct clientCommand
{
	uint64_t seqNo;
	pubkey_t user_pubkey;
	struct private_command eCMD;
};

struct dynamicDS
{
	size_t buffer_size;
	uint8_t * buffer;
};

struct dAppData
{
	int num_dDS;
	struct dynamicDS *dDS;
};



void init_enclave_state(struct ES * enclave_state,  struct dAppData * dAD);
sgx_status_t unseal_enclave_state(const sgx_sealed_data_t * sealedstate, bool ecall_CMD, struct ES * enclave_state, struct dAppData * dAD);
sgx_status_t seal_enclave_state(struct ES * enclave_state, struct dAppData * dAD, size_t sealedstate_size, const sgx_sealed_data_t * sealedstate);
void free_enclave_state(struct ES * enclave_state, struct dAppData * dAD);

size_t calc_auditlog_buffer_size(struct ES * enclave_state);
sgx_status_t ecall_init_buffer_sizes(uint64_t num_users, size_t *newsealedstate_size);
sgx_status_t ecall_cmd_buffer_sizes(uint8_t *sealedstate, size_t sealedstate_size, size_t *newsealedstate_size);
sgx_status_t ecall_audit_buffer_sizes(uint8_t *sealedstate, size_t sealedstate_size, size_t *newsealedstate_size, size_t *newauditlog_buffer_size);

#endif
