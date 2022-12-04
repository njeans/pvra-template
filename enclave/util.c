//#include <secp256k1.h>
//#include <secp256k1_recovery.h>
#include <sgx_tcrypto.h>


//#include "enclave_state.h"
#include "keccak256.h"
#include "util.h"


void get_address(secp256k1_pubkey * pubkey, address_t* out) {
    struct SHA3_CTX ctx;
    keccak_init(&ctx);
    keccak_update(&ctx, pubkey, 64);
    unsigned char result[HASH_SIZE];
    keccak_final(&ctx, result);
    memcpy(out, &result[12], sizeof(address_t));
}

//solidity abi.encodePacked([]address) function left pads address to 32 bytes
void get_packed_address(secp256k1_pubkey * pubkey, packed_address_t* out) {
    struct SHA3_CTX ctx;
    keccak_init(&ctx);
    keccak_update(&ctx, pubkey, 64);
    unsigned char result[HASH_SIZE];
    keccak_final(&ctx, result);
    memset(out, 0, sizeof(packed_address_t));
    memcpy((char *)out + 12, &result[12], sizeof(address_t));
}

void keccak256(uint8_t *buff, size_t buff_size, uint8_t * hash_out_32) {
  char eth_prefix[100];
  int len_prefix = sprintf(eth_prefix,"%cEthereum Signed Message:\n%d",25, buff_size);
  struct SHA3_CTX ctx;
  keccak_init(&ctx);
  keccak_update(&ctx, eth_prefix, len_prefix-1);
  keccak_update(&ctx, buff, buff_size);
  keccak_final(&ctx, hash_out_32);
}

void hash_address_list(secp256k1_pubkey * admin_pubkey, secp256k1_pubkey * user_pubkeys_list, int num_pubkeys, uint8_t * hash_out_32) {
  packed_address_t * addr_buff = (packed_address_t *) calloc(num_pubkeys+1, sizeof(packed_address_t)); // todo check null
  size_t addr_buff_len = sizeof(packed_address_t)*(num_pubkeys+1);
  get_packed_address(admin_pubkey, addr_buff);
  for (int i = 0; i < num_pubkeys; i++) {
    get_packed_address(&user_pubkeys_list[i], &addr_buff[i+1]);
  }
  keccak256(addr_buff, addr_buff_len, hash_out_32);
  free(addr_buff);
}


void memcpy_big_uint32(uint8_t* buff, uint32_t num) {
    int x = 1;
    char *p = (char *)&x;
    uint32_t swapped;
	if (p[0] == 1){
        swapped = __builtin_bswap32(num);
    } else {
        swapped = num;
    }
   memcpy(buff, &swapped, 4);
}

void memcpy_big_uint64(uint8_t* buff, uint64_t num) {
    int x = 1;
    char *p = (char *)&x;
    uint64_t swapped;
	if (p[0] == 1){
        swapped = __builtin_bswap64(num);
    } else {
        swapped = num;
    }
   memcpy(buff, &swapped, 8);
}

void hexstr_to_bytes(char * hexstr, size_t len, uint8_t * bytes) {
    for(int j = 0; j < len; j+=2) {

      char c1 = hexstr[j];
      int value1 = 0;
      if(c1 >= '0' && c1 <= '9')
        value1 = (c1 - '0');
      else if (c1 >= 'A' && c1 <= 'F')
        value1 = (10 + (c1 - 'A'));
      else if (c1 >= 'a' && c1 <= 'f')
        value1 = (10 + (c1 - 'a'));

      char c0 = hexstr[j+1];
      int value0 = 0;
      if(c0 >= '0' && c0 <= '9')
        value0 = (c0 - '0');
      else if (c0 >= 'A' && c0 <= 'F')
        value0 = (10 + (c0 - 'A'));
      else if (c0 >= 'a' && c0 <= 'f')
        value0 = (10 + (c0 - 'a'));
      bytes[j/2] = (value1<<4) | value0;
    }
}

sgx_status_t genkey_secp256k1(unsigned char seed, secp256k1_prikey * out_seckey, secp256k1_pubkey *out_pubkey, unsigned char *out_pubkey_ser) {
  unsigned char randomize[32];
  int err;
  sgx_status_t ret = sgx_read_rand(randomize, sizeof(randomize));
  if (ret != SGX_SUCCESS) {
    printf("[genkey_secp256k1] sgx_read_rand() failed!\n");
    return ret;
  }
  if(DETERMINISTIC_KEYS) {
    memset(out_seckey, seed, sizeof(secp256k1_prikey));
  } else {
    ret = sgx_read_rand(out_seckey, sizeof(secp256k1_prikey));
    if (ret != SGX_SUCCESS) {
        printf("[genkey_secp256k1] sgx_read_rand() failed!\n");
        return ret;
    }
  }

  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  if (ctx == NULL) {
    printf("[genkey_secp256k1] secp256k1_context_create failed\n");
    return SGX_ERROR_UNEXPECTED;
  }
  err = secp256k1_context_randomize(ctx, randomize);
  if (err != 1) {
    printf("[genkey_secp256k1] secp256k1_context_randomize failed %d\n", err);
    return SGX_ERROR_UNEXPECTED;
  }
  err = secp256k1_ec_pubkey_create(ctx, out_pubkey, out_seckey);
  if (err != 1) {
    printf("[genkey_secp256k1] secp256k1_ec_pubkey_create failed %d\n", err);
    return SGX_ERROR_UNEXPECTED;
  }
  if (out_pubkey_ser != NULL){
      size_t encpubkey_ser_len = 65;
      secp256k1_ec_pubkey_serialize(ctx, out_pubkey_ser, &encpubkey_ser_len, out_pubkey, SECP256K1_EC_UNCOMPRESSED);
      if (encpubkey_ser_len != 65) {
        printf("[genkey_secp256k1] secp256k1_ec_pubkey_serialize failed %lu!=65\n", encpubkey_ser_len);
        return SGX_ERROR_UNEXPECTED;
      }
  }

  secp256k1_context_destroy(ctx);
  return SGX_SUCCESS;
}

//todo return int?
sgx_status_t sign_secp256k1(secp256k1_prikey seckey, unsigned char data_hash[HASH_SIZE], secp256k1_ecdsa_signature *out_sig, unsigned char *sig_ser) {
  unsigned char randomize[32];
  int err;

  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  if (ctx == NULL) {
    printf("[sign_secp256k1] secp256k1_context_create failed\n");
    return SGX_ERROR_UNEXPECTED;
  }
  sgx_status_t ret = sgx_read_rand(randomize, sizeof(randomize));
  if (ret != SGX_SUCCESS) {
    printf("[sign_secp256k1] sgx_read_rand() failed!\n");
    return ret;
  }
  err = secp256k1_context_randomize(ctx, randomize);
  if (err != 1) {
    printf("[sign_secp256k1] secp256k1_context_randomize failed %d\n", err);
    return SGX_ERROR_UNEXPECTED;
  }
  err = secp256k1_ecdsa_sign(ctx, out_sig, data_hash, seckey, NULL, NULL);
  if (err != 1) {
    printf("[sign_secp256k1] secp256k1_ecdsa_sign failed %d\n", err);
    return SGX_ERROR_UNEXPECTED;
  }
  if (sig_ser != NULL){
    err = secp256k1_ecdsa_signature_serialize_compact(ctx, sig_ser, out_sig);
    if (err != 1) {
        printf("[sign_secp256k1] secp256k1_ecdsa_signature_serialize_compact failed %d\n", err);
        return SGX_ERROR_UNEXPECTED;
    }
  }
  secp256k1_context_destroy(ctx);
  return SGX_SUCCESS;
}

sgx_status_t sign_rec_secp256k1(secp256k1_prikey seckey, unsigned char data_hash[HASH_SIZE], secp256k1_ecdsa_recoverable_signature *out_sig, unsigned char *sig_ser) {
  unsigned char randomize[32];
  int err;

  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  if (ctx == NULL) {
    printf("[sign_rec_secp256k1] secp256k1_context_create failed\n");
    return SGX_ERROR_UNEXPECTED;
  }
  sgx_status_t ret = sgx_read_rand(randomize, sizeof(randomize));
  if (ret != SGX_SUCCESS) {
    printf("[sign_rec_secp256k1] sgx_read_rand() failed!\n");
    return ret;
  }
  err = secp256k1_context_randomize(ctx, randomize);
  if (err != 1) {
    printf("[sign_rec_secp256k1] secp256k1_context_randomize failed %d\n", err);
    return SGX_ERROR_UNEXPECTED;
  }
  err = secp256k1_ecdsa_sign_recoverable(ctx, out_sig, data_hash, seckey, NULL, NULL);
  if (err != 1) {
    printf("[sign_rec_secp256k1] secp256k1_ecdsa_sign failed %d\n", err);
    return SGX_ERROR_UNEXPECTED;
  }
  if (sig_ser != NULL){
    int recovery;
    err = secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig_ser, &recovery, out_sig);
    if (err != 1) {
        printf("[sign_rec_secp256k1] secp256k1_ecdsa_signature_serialize_compact failed %d\n", err);
        return SGX_ERROR_UNEXPECTED;
    }
    uint8_t v = ((uint8_t) recovery);
    uint8_t p = (uint8_t) 27;
    v = v + p;
    sig_ser[64] = v;
  }
  secp256k1_context_destroy(ctx);
  return SGX_SUCCESS;
}

sgx_status_t genkey_aesgcm128(uint8_t other_pubkey[64], uint8_t my_privkey[32], unsigned char AESkey[AESGCM_128_KEY_SIZE]){
  int err;
  unsigned char randomize[32];
  unsigned char shared_secret[32];
  secp256k1_pubkey user_pubkey;
  char user_pubkey_buff[65];
  user_pubkey_buff[0] = SECP256K1_TAG_PUBKEY_UNCOMPRESSED;
  memcpy(&user_pubkey_buff[1], other_pubkey, 64);

  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);//todo check null
  sgx_status_t ret = sgx_read_rand(randomize, sizeof(randomize));
  if (ret != SGX_SUCCESS) {
    printf("[genkey_aesgcm128] sgx_read_rand() failed!\n");
    return ret;
  }

  err = secp256k1_context_randomize(ctx, randomize);
  if(err == 0) {
    printf("[genkey_aesgcm128] secp256k1_context_randomize() failed\n");
    return SGX_ERROR_UNEXPECTED;
  }
  //todo validate keys in initPVRA

  err = secp256k1_ec_pubkey_parse(ctx, &user_pubkey, user_pubkey_buff, 65); //todo use flags in secp.h
  if(err == 0) {
    printf("[genkey_aesgcm128] secp256k1_ec_pubkey_parse() failed\n");
    return SGX_ERROR_UNEXPECTED;
  }

  err = secp256k1_ecdh(ctx, shared_secret, &user_pubkey, my_privkey, NULL, NULL);
  if(err == 0) {
    printf("[genkey_aesgcm128] secp256k1_ecdh() failed\n");
    return SGX_ERROR_UNEXPECTED;
  }
  memcpy(AESkey, shared_secret, AESGCM_128_KEY_SIZE);
  secp256k1_context_destroy(ctx);
  return SGX_SUCCESS;
}

sgx_status_t encrypt_aesgcm128(uint8_t AESKey[AESGCM_128_KEY_SIZE], uint8_t * buff, size_t buff_size, uint8_t * enc_out){

  uint8_t *tag_dst = enc_out;
  uint8_t *iv_src = enc_out + AESGCM_128_MAC_SIZE;
  uint8_t *ct_dst = enc_out + AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE;
  sgx_status_t ret = sgx_read_rand(iv_src, AESGCM_128_IV_SIZE);
  if (ret != SGX_SUCCESS) {
    printf("[enc_aesgcm128] sgx_read_rand() failed!\n");
    return ret;
  }
  ret = sgx_rijndael128GCM_encrypt((sgx_aes_gcm_128bit_key_t *) AESKey,
                                        buff, buff_size,
                                        ct_dst,
                                        iv_src, AESGCM_128_IV_SIZE,
                                        NULL, 0,
                                        tag_dst);

  if(C_DEBUGRDTSC) ocall_rdtsc();
  return ret;
}
