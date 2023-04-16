// for development, set to 1, 0, 0 for production deployments
#define CCF_ENABLE 1
#define DETERMINISTIC_KEYS 1
#define DEBUGPRINT 1

#define I_DEBUGRDTSC 0
#define C_DEBUGRDTSC 0
#define A_DEBUGRDTSC 0


#define HASH_SIZE 32
#define AESGCM_128_KEY_SIZE 16
#define AESGCM_128_MAC_SIZE 16
#define AESGCM_128_IV_SIZE 12

typedef uint8_t secp256k1_prikey[32];
typedef uint8_t address_t[20];
typedef uint8_t packed_address_t[32];
