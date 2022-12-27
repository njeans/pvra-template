#include <enclave_t.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include "constants.h"
#include "enclave_state.h"
#include <netdb.h>


struct ccf_node
{
    bool is_left;
    uint8_t data[HASH_SIZE];
};

struct ccf_proof
{
    uint8_t commit_evidence_digest[HASH_SIZE];
    uint8_t write_set_digest[HASH_SIZE];
    uint8_t FT[HASH_SIZE];
    uint64_t proof_len;
    struct ccf_node* proof;
};

int parse_ccf_proof(uint8_t * buff, size_t buff_size, struct ccf_proof* out);

void free_ccf_proof(struct ccf_proof* out);

int check_ccf_proof(struct ccf_proof* proof, uint8_t *sig, size_t sig_len);

sgx_status_t sign_cResponse(uint8_t seckey[32], struct cResponse * cResp, unsigned char *sig_ser);

sgx_status_t encrypt_cResponse(unsigned char AESKey[AESGCM_128_KEY_SIZE], struct cResponse * cResp, uint8_t * enc_cResponse, size_t enc_cResponse_size);

void get_packed_address(pubkey_t * pubkey, packed_address_t* out);

void hash_address_list(pubkey_t * admin_pubkey, pubkey_t * user_pubkeys_list, uint64_t num_pubkeys, uint8_t * hash_out_32);

void keccak256(uint8_t *buff, size_t buff_size, uint8_t * hash_out_32);

void sha256(uint8_t *buff, size_t buff_size, uint8_t * hash_out_32);

void memcpy_big_uint32(uint8_t* buff, uint32_t val);

void hexstr_to_bytes(char * hexstr, size_t len, uint8_t * bytes);

sgx_status_t genkey_secp256k1(unsigned char seed, secp256k1_prikey * out_seckey, secp256k1_pubkey *out_pubkey, unsigned char *out_pubkey_ser);

sgx_status_t sign_secp256k1(secp256k1_prikey seckey, unsigned char data_hash[HASH_SIZE], secp256k1_ecdsa_signature *out_sig, unsigned char *sig_ser);

sgx_status_t sign_rec_secp256k1(secp256k1_prikey seckey, unsigned char data_hash[HASH_SIZE], secp256k1_ecdsa_recoverable_signature *out_sig, unsigned char *sig_ser);

sgx_status_t genkey_aesgcm128(uint8_t other_pubkey[64], uint8_t my_privkey[32], unsigned char AESkey[AESGCM_128_KEY_SIZE]);

sgx_status_t encrypt_aesgcm128(unsigned char AESKey[AESGCM_128_KEY_SIZE], uint8_t * buff, size_t buff_size, uint8_t * enc_out);

int ocall_close(int sockfd);

// int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo *res);