#include <secp256k1.h>
#include "keccak256.h"
#include "enclavestate.h"


void get_address(secp256k1_pubkey * pubkey, address_t* out) {
    struct SHA3_CTX ctx;
    keccak_init(&ctx);
    keccak_update(&ctx, pubkey, 64);
    unsigned char result[32];
    keccak_final(&ctx, result);
    memcpy(out, &result[12], sizeof(address_t));
}

void get_packed_address(secp256k1_pubkey * pubkey, packed_address_t* out) {
    struct SHA3_CTX ctx;
    keccak_init(&ctx);
    keccak_update(&ctx, pubkey, 64);
    unsigned char result[32];
    keccak_final(&ctx, result);
    memcpy((char *)out + 12, &result[12], sizeof(address_t));
//    printf("get_packed_address_result=");
//    print_hexstring(result, sizeof(result));
//    printf("get_packed_address_out=");
//    print_hexstring(out, sizeof(packed_address_t));
}

//solidity abi.packed([]address) function left pads address to 32 bytes
void hash_address_list(secp256k1_pubkey * pubkey_list, int num_pubkeys, char * hash_out_32) {
  packed_address_t * addr_buff = (packed_address_t *) calloc(num_pubkeys, sizeof(packed_address_t));//todo check null
  for (int i = 0; i < num_pubkeys; i++) {
    get_packed_address(&pubkey_list[i], &addr_buff[i]);
  }
  char eth_prefix[100];
  int s = sprintf(eth_prefix,"%cEthereum Signed Message:\n%d", 25, sizeof(packed_address_t) * num_pubkeys);
//  printf("address_buff=");
//  print_hexstring(addr_buff, num_pubkeys*sizeof(packed_address_t));
  struct SHA3_CTX ctx_sha3;
  keccak_init(&ctx_sha3);
  //s-1 don't want '{0}' string deliminator
  keccak_update(&ctx_sha3, eth_prefix, s-1);
  keccak_update(&ctx_sha3, addr_buff, sizeof(packed_address_t)*num_pubkeys );
  keccak_final(&ctx_sha3, hash_out_32);
  free(addr_buff);
}

