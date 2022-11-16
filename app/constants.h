// for development, set to 1 for production deployments
#define CCF_ENABLE 0
#define DETERMINISTIC_KEYS 1

#define I_DEBUGRDTSC 0
#define C_DEBUGRDTSC 0
#define A_DEBUGRDTSC 0

#define DEBUGPRINT 1


#define HASH_SIZE 32
#define AESGCM_128_KEY_SIZE 16
#define AESGCM_128_MAC_SIZE 16
#define AESGCM_128_IV_SIZE 12

// [TODO]: make these parameters dynamic? not sure if it is worth it right now
#define MAX_USERS 10
#define MAX_LOG_SIZE 100

typedef unsigned char secp256k1_prikey[32];
typedef unsigned char address_t[20];
typedef unsigned char packed_address_t[32];
