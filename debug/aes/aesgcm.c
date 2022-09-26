/* Simple AES GCM test program, uses the same NIST data used for the FIPS
 * self test but uses the application level EVP APIs.
 */
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdbool.h>


FILE *open_file(const char *const filename, const char *const mode) {
  return fopen(filename, mode);
}

#define NUM_COMMANDS 2

typedef enum { COMMAND0, COMMAND1 } eType;


struct cType 
{
	int tid;
};


struct cInputs
{
	int uid;
	int test_result;
};

struct clientCommand
{
	struct cType CT;
	struct cInputs CI;
	int seqNo;
	int cid;
};



/* AES-GCM test data from NIST public test vectors */

static const unsigned char gcm_key[] = {
	0xee,0xbc,0x1f,0x57,0x48,0x7f,0x51,0x92,0x1c,0x04,0x65,0x66,
	0x5f,0x8a,0xe6,0xd1,0x65,0x8b,0xb2,0x6d,0xe6,0xf8,0xa0,0x69,
	0xa3,0x52,0x02,0x93,0xa5,0x72,0x07,0x8f
};

/*uint8_t aes128_key[] = {
	0x29,0x58,0x04,0x8c,0x2d,0x96,0x3b,0x5c,0xec,0x7f,0xba,0x59,
	0x5b,0x47,0x7a,0x42
};*/

uint8_t aes128_key[] = {
	0x57,0x4b,0x73,0x58,0x04,0xac,0x02,0xfb,0xc6,0xf3,0x5c,0x71,
	0x7a,0x62,0x95,0x8d
};

/*static const unsigned char gcm_iv[] = {
	0x99,0xaa,0x3e,0x68,0xed,0x81,0x73,0xa0,0xee,0xd0,0x66,0x84
};*/

static const unsigned char gcm_iv[] = {
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};


static const unsigned char gcm_pt[] = {
	0x7B,0x75,0x73,0x65,0x72,0x5F,0x64,0x61,0x74,0x61,0x7D,0x00,
	0x00,0x00,0x00,0x00
};

/*static const unsigned char gcm_pt[] = {
	0xf5,0x6e,0x87,0x05,0x5b,0xc3,0x2d,0x0e,0xeb,0x31,0xb2,0xea,
	0xcc,0x2b,0xf2,0xa5
};*/


static const unsigned char gcm_aad[] = {
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00
};

/*static const unsigned char gcm_ct[] = {
	0xf7,0x26,0x44,0x13,0xa8,0x4c,0x0e,0x7c,0xd5,0x36,0x86,0x7e,
	0xb9,0xf2,0x17,0x36
};*/

static const unsigned char gcm_ct[] = {
	0xf7,0x2d,0x26,0xe3,0xee,0xbb,0x7a,0xff,0x8c,0x7c,0x9e,0xd6,
	0x39,0x8a,0x66,0x86
};

//3960a364143b4d9f8ba0e54475544fb7b8f8bad4b10fe21cb89093d51b03a88a96004ccf9cec359d45f77363

/*static const unsigned char gcm_tag[] = {
	0x67,0xba,0x05,0x10,0x26,0x2a,0xe4,0x87,0xd7,0x37,0xee,0x62,
	0x98,0xf7,0x7e,0x0c
};*/

static const unsigned char gcm_tag[] = {
	0x7b,0x96,0x30,0xa2,0x25,0x27,0xbd,0x5c,0x36,0xd3,0x7c,0x89,
	0x8e,0x09,0x02,0xcb
};

#define AESGCM_128_KEY_SIZE 16
#define AESGCM_128_MAC_SIZE 16
#define AESGCM_128_IV_SIZE 12

bool read_file_into_memory(const char *const filename, void **buffer,
                           size_t *buffer_size) {
  bool ret_status = true;
  FILE *file = NULL;
  long file_len = 0L;

  if (buffer == NULL || buffer_size == NULL) {
    fprintf(stderr,
            "[GatewayApp]: read_file_into_memory() invalid parameter\n");
    ret_status = false;
    goto cleanup;
  }

  /* Read sensor data from file */
  file = open_file(filename, "rb");
  if (file == NULL) {
    fprintf(stderr, "[GatewayApp]: read_file_into_memory() fopen failed\n");
    ret_status = false;
    goto cleanup;
  }

  fseek(file, 0, SEEK_END);
  file_len = ftell(file);
  if (file_len < 0 || file_len > INT_MAX) {
    fprintf(stderr, "[GatewayApp]: Invalid input file size\n");
    ret_status = false;
    goto cleanup;
  }

  *buffer_size = (size_t)file_len;
  *buffer = malloc(*buffer_size);
  if (*buffer == NULL) {
    fprintf(stderr,
            "[GatewayApp]: read_file_into_memory() memory allocation failed\n");
    ret_status = false;
    goto cleanup;
  }

  fseek(file, 0, SEEK_SET);
  if (fread(*buffer, *buffer_size, 1, file) != 1) {
    fprintf(stderr, "[GatewayApp]: Input file only partially read.\n");
    ret_status = false;
    goto cleanup;
  }

cleanup:
  if (file != NULL) {
    fclose(file);
  }

  return ret_status;
}

void aes_gcm_encrypt(char* tid, char* uid, char* res, char* sno, char* cid, char* key_path)
	{

	struct clientCommand CC;
	CC.CT.tid = atoi(tid);
	CC.CI.uid = atoi(uid);
	CC.CI.test_result = (char) (atoi(res) && 0xF);
	CC.seqNo = atoi(sno);
	CC.cid = atoi(cid);
  printf("[ecPVRA]: Readable eCMD: {[CT]:%d [CI]:%d,%d [SN]:%d [ID]:%d}\n", CC.CT.tid, CC.CI.uid, CC.CI.test_result, CC.seqNo, CC.cid);

  	char* pt = &CC;

	uint8_t eCMD_full[2048] = {0};

	//printf("%s %d\n", pt, strlen(pt));
	EVP_CIPHER_CTX *ctx;
	int outlen, tmplen;
	unsigned char outbuf[1024];
	printf("AES GCM Encrypt:\n");
	printf("Plaintext:\n");
	BIO_dump_fp(stdout, gcm_pt, sizeof(gcm_pt));


	ctx = EVP_CIPHER_CTX_new();
	/* Set cipher type and mode */
	//printf("%d\n", EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL));
	/* Set IV length if default 96 bits is not appropriate */
	//printf("%d\n", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(gcm_iv), NULL));
	/* Initialise key and IV */

	void *new_buffer;
	size_t new_buffer_size;
	bool ret_status = read_file_into_memory(key_path, &new_buffer, &new_buffer_size);

	print_hexstring(new_buffer, new_buffer_size);

	printf("SIZE OF BUFFER %d\n", new_buffer_size);
	





	printf("%d\n", EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, new_buffer, gcm_iv));
	/* Zero or more calls to specify any AAD */
	//printf("%d\n", EVP_EncryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad)));
	/* Encrypt plaintext */
	printf("%d\n", EVP_EncryptUpdate(ctx, outbuf, &outlen, pt, sizeof(struct clientCommand)));
	/* Output encrypted block */
	printf("Ciphertext:\n");
	BIO_dump_fp(stdout, outbuf, outlen);


  uint8_t *ct_src = &eCMD_full[AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE];
  uint8_t *iv_src = &eCMD_full[AESGCM_128_MAC_SIZE];
  uint8_t *tag_src = eCMD_full;


  memcpy(eCMD_full + AESGCM_128_MAC_SIZE, gcm_iv, AESGCM_128_IV_SIZE);
  memcpy(eCMD_full + AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE, outbuf, outlen);

  int ct_len = outlen;


	/* Finalise: note get no output for GCM */
	EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
	/* Get tag */
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, outbuf);
	/* Output tag */
	printf("Tag:\n");
	BIO_dump_fp(stdout, outbuf, 16);

  memcpy(eCMD_full, outbuf, AESGCM_128_MAC_SIZE);
  print_hexstring(eCMD_full, AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE + ct_len);

FILE *file = fopen("eCMD.bin", "wb");
fwrite(&eCMD_full, sizeof(char), AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE + ct_len, file);
fclose(file);



	EVP_CIPHER_CTX_free(ctx);
	}

void print_hexstring(const void *vsrc, size_t len) {
  const unsigned char *sp = (const unsigned char *)vsrc;
  size_t i;
  for (i = 0; i < len; ++i) {
    printf("%02x", sp[i]);
  }
  printf("\n");
}

void aes_gcm_encrypt128(void)
	{

	uint8_t eCMD_full[2048] = {0x0a};


	EVP_CIPHER_CTX *ctx;
	int outlen, tmplen;
	unsigned char outbuf[1024];
	printf("AES GCM Encrypt:\n");
	printf("Plaintext:\n");
	BIO_dump_fp(stdout, gcm_pt, sizeof(gcm_pt));
	ctx = EVP_CIPHER_CTX_new();
	/* Set cipher type and mode */
	EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
	/* Set IV length if default 96 bits is not appropriate */
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(gcm_iv), NULL);
	/* Initialise key and IV */
	EVP_EncryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);
	/* Zero or more calls to specify any AAD */
	EVP_EncryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
	/* Encrypt plaintext */
	EVP_EncryptUpdate(ctx, outbuf, &outlen, gcm_pt, sizeof(gcm_pt));
	/* Output encrypted block */
	printf("Ciphertext:\n");
	BIO_dump_fp(stdout, outbuf, outlen);

  uint8_t *ct_src = &eCMD_full[AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE];
  uint8_t *iv_src = &eCMD_full[AESGCM_128_MAC_SIZE];
  uint8_t *tag_src = eCMD_full;


  memcpy(eCMD_full + AESGCM_128_MAC_SIZE, gcm_iv, AESGCM_128_IV_SIZE);
  memcpy(eCMD_full + AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE, outbuf, outlen);

	/* Finalise: note get no output for GCM */
	EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
	/* Get tag */
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, outbuf);
	/* Output tag */
	printf("Tag:\n");
	BIO_dump_fp(stdout, outbuf, 16);

  memcpy(eCMD_full, outbuf, AESGCM_128_MAC_SIZE);
  print_hexstring(eCMD_full, AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE + outlen);

	EVP_CIPHER_CTX_free(ctx);
	}

void aes_gcm_decrypt(void)
	{
	EVP_CIPHER_CTX *ctx;
	int outlen, tmplen, rv;
	unsigned char outbuf[1024];
	printf("AES GCM Derypt:\n");
	printf("Ciphertext:\n");
	BIO_dump_fp(stdout, gcm_ct, sizeof(gcm_ct));
	ctx = EVP_CIPHER_CTX_new();
	/* Select cipher */
	EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
	/* Set IV length, omit for 96 bits */
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(gcm_iv), NULL);
	/* Specify key and IV */
	EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);
#if 0
	/* Set expected tag value. A restriction in OpenSSL 1.0.1c and earlier
         * required the tag before any AAD or ciphertext */
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(gcm_tag), gcm_tag);
#endif
	/* Zero or more calls to specify any AAD */
	EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
	/* Decrypt plaintext */
	EVP_DecryptUpdate(ctx, outbuf, &outlen, gcm_ct, sizeof(gcm_ct));
	/* Output decrypted block */
	printf("Plaintext:\n");
	BIO_dump_fp(stdout, outbuf, outlen);
	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(gcm_tag), gcm_tag);
	/* Finalise: note get no output for GCM */
	rv = EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
	/* Print out return value. If this is not successful authentication
	 * failed and plaintext is not trustworthy.
	 */
	printf("Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");
	EVP_CIPHER_CTX_free(ctx);
	}

int main(int argc, char **argv)
	{
	aes_gcm_encrypt(argv[1], argv[2], argv[3], argv[4], argv[5], argv[6]);
	//aes_gcm_decrypt();
	}
