#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>


#include <assert.h>

#include <stdbool.h>

#include <string.h>


const char* b64pub = "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJDZ0tDQVFFQXJzWUpF\nQW42OHRNS3laR0NNNk94K0h4MDlxQW5RVE95Q1pMODkxWEN6MStqTG5CT25LRW8K\nRnpQZm0va0J3NUhTdS9PdkUwVXRObDJiSkRXZ2t4bW15NU8xKzcvOGZVSmFabjZV\nYTA4L2Q2Yk9EK29NV3BsSQp2SVdPWG5nbWdUZFdaVFlJb2E0NWZqa215eFFwUVQx\ncTg1QVQrcW0vME56WXVuSTVabGNzMks4REJQMW1mYUdrCnpyOGF4bE44SExQWnEz\nazlLTHZCeVFZSEw5dEZyTlE4VEZiM0UxdG5zNEpwRlA1cGJKSi9SczRRWkpOeEtD\nTDYKY3hUeDRnY2xaRnljSnVISUJheTJEeVJCTS9Sb2o5eTFNRnVackduWHh3Qi8z\nNXFtWGNtOXBiQktjY1pGNHJBSwpUSGNmcnRBM3ZwZjlGWlpIdEVpWmJ1SjYwMGli\nQ25wZXV3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K\n";


const char* b64pri = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb2dJQkFBS0NBUUVB\nNjhIK0xDUTNuMlFhVFpLNTdlZnB4OFNhNFRzSnVEOEtISTVUVTBLWHlUcVV3aDRt\nCnJXeTNKdHh5ZmNpeFl4Qm5rUkpZRkt1eklhUkFwYmVTbjkzcE14NzNCUHBlS3Bx\nY0swRnhRTHBqY3AzaW9MakMKbHBPWlQrWlgzS1pQaHd0aUIvSUk4NGNrbE43bnEx\nc3c4dUxjZlV0R3NwRDZPcVAyMmUwcTlQeTZpMmRaUmc0UwovcFdYenBpY3hMVEVK\nOTJZME1SUkJ0bENMWW1MM3BLRnZST3BZN001S2szUFFXMnB2Z3JjOEJLQ3NoSmQy\nNGEyCjlyQzIrTWYrNWE3dEpIelBJc3JVcml1S202S01XWWxqZW5DckswbkNWVzRU\nUTFFTE9sdkE2WUExRUR4bERVVVoKUUtYM3diOE1tdHIzRGpLSjByS1RSUStpbWx0\nNXdVSHZ4cG4welFJREFRQUJBb0gvUHA5STVIQzZWWnhCWUZtWgpDWmlRZ0grNHBC\nc0tlZVpFeVZFRTBSamZPSlJXN3prVERQM1RxSDdsNm9Oa211dkFsc2hJblRUK1gv\nRkJPc09JCkx1N0RBdEUyekJ1MDU1d3AzMU9Dd2E3QXU3RTBnWHlTTTIwQlREZmpI\ncmtPWnRDZk9YMFE0NThDR0lrZEFHYzQKbVV1cFJaNjVLTFZad2puTFdCZW5VV3ZR\nSVRiUDZDZEgyQ1NYQmlTb2JKZHhzSHBFbG5Ndnk4NjZGZUwrZHdoQQpsaGo3cHNK\nSTJ6MHkyV2ZIV25FQjkvM0hKKzM4OVovMVBjaVlRLzR5Y2dqRkZ2ekxqNDFlNlVn\nMCtWd05ZRGJlCk12dnFYSHpXZTVMUVhDblhLNlhNNmVVMHVQZWkremVpaVJpcnZm\nRDdWQk16T0ZSelp6MWM1aHpWRTVTVSs1aGsKdXZmeEFvR0JBUDVyTkx2aVVNRkE3\nZEdzeTRmcWVxNXkxdjFvSzNIL2xZd21SVzRiNndqRGs2OWRmTTU4WWlGbwo3d3JD\nOUtaWmNiMTlua0V5WHRKUkd1Z3JwdlFLSnhOcFRiWDdMNWRBUUEyUlpXNU9JNmlK\ncU5NZE9VWXN3UnBXClRvdTRlb3JiblBleHoreDdKZVRnSEUzMUw1NzJhN09iN2cz\nT0J1amM2Mnl3dlkvVE9CckhBb0dCQU8wNUdLSnAKdTZ5RFlMSmVnRkhGTmVaYk9Y\naFhLOWdjbFpUNzk1R0pRTlpHdmVXWjUySlIxSFpxM2pvTFBPNmRmak9ibWJaRgpT\ndnNPNEEyTCs5NUliTUV3cHNvaGQ3MnYxeG9oZldTT3ZZVVlsT1FKZXpiQUR5K2lO\ncnFibEVYL1E3allQaVlzCktMVmZWTG5kN1I2QzlVQ2hXRG1tTDJKd2x2dmlyRjY1\nakgvTEFvR0FjdGZUdXdmaXFnbDBFSlN1WHhEaUJnTUMKdHVxaHlkaTBHY3BneHQ1\nRlR2UnhvdFJSZFNmQ2FCQms3dmVuMWJ0RVUyUHozcndzLzBUckgyZ3MrYlhuZzZT\naQpGb1puS2lBdmliQmJGOXFmMEFFcnV2aFRGVEU0alhudUJMWG1ZdTNWUWgzNm5H\nWE9haTBidWJqMm9RdmMrL3RrCkRzazBaMExwNW1zMWRrbkM1cHNDZ1lFQXBjNkZv\nR2VFektTYlByRDh3YXEwN01pUVY4T2VHcFNJSExVc3FpV2sKRXVFcE04VXB6RGZq\nNTh6MGZOK0QvRWhLZ0duZXUxNmRkUE5GdVZKQmZuRml5bmxsNnR3UHBKNjJHMGFU\nTFdqegpvSWE0OHRhSnI0LzRUVlAxS3VNNWROOWhoMTVsdWlxZFhZQS9hUlpyK1Nx\nUm4xWG1vNHk3aS9Pa0pIU2dCQ2x1CndaY0NnWUVBcXloVnRLVHNLZm5mWURRdnNG\nQzRBcmRYU2JEVXNTZDdWYnhXS2R6OEpQWVQ4M1V3RmpTSE56c04KZmRRVkIzZGRR\nekJWZVEzdzllSTNlWFNKdS9vTERsK05FeTJ4K2tRMWFNUHNtV0grYXVMUzJoNURt\nQkt4djJWQgpnL2VrUFNWWVVYblQ2QzErNmZqQWxqSmRkRU9hVDhaS1pId0FDWTBP\nMW9wWGJSQ0tSVTA9Ci0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg==\n";

const char* message = "fc857532b55796a46aace6a53c3392763b7be4a43f05526888da5a57438b120e";

const char* b64sig = "r+yGWYYZ0Hl4nJXsm2xiX4XrG+DPyWcQlXsh7X4ZhTLOc3bbCh53zvDOKgSRyclQ\nip1HeWukzXe7Lp0hBWc//MX0fTLnt7sEt2pNoFjmHg4Wgvp6ZFy3fuk3k0+R+s7t\nuFGWjMFHWv5+y24IL2HYeJwmUMeb2V6A9cCuu0IEAwPjgOuSEfjdXJSqtPwbHwZ9\nHQJ379ZNcXK3Zm3rE3XGLnoQqCm7qf/gZSZSAZUZhGXhDCXJ2h1oPC47XCYcjtVk\n3WnBTxKDF0wbBfAevHDwliCSErT0COKwLKhhc25jjHu/qdEfFfo6cL0gVj45WXJ+\noaGeOrvVTaXbPVOC1KjdnQ==\n";


void Base64Encode( const unsigned char* buffer,
                   size_t length,
                   char** base64Text) {
  BIO *bio, *b64;
  BUF_MEM *bufferPtr;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);

  BIO_write(bio, buffer, length);
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bufferPtr);
  BIO_set_close(bio, BIO_NOCLOSE);
  BIO_free_all(bio);

  *base64Text=(*bufferPtr).data;
}


size_t calcDecodeLength(const char* b64input) { 
  size_t len = strlen(b64input), padding = 0;

  if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
    padding = 2;
  else if (b64input[len-1] == '=') //last char is =
    padding = 1;
  return (len*3)/4 - padding;
}

void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
  BIO *bio, *b64;

  int decodeLen = calcDecodeLength(b64message);
  *buffer = (unsigned char*)malloc(decodeLen + 1);
  (*buffer)[decodeLen] = '\0';

  bio = BIO_new_mem_buf(b64message, -1);
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);

  *length = BIO_read(bio, *buffer, strlen(b64message));
  BIO_free_all(bio);
}

bool RSAVerifySignature( RSA* rsa,
                         unsigned char* MsgHash,
                         size_t MsgHashLen,
                         const char* Msg,
                         size_t MsgLen,
                         bool* Authentic) {
  *Authentic = false;
  EVP_PKEY* pubKey  = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(pubKey, rsa);
  EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

  if (EVP_DigestVerifyInit(m_RSAVerifyCtx,NULL, EVP_sha256(),NULL,pubKey)<=0) {
    return false;
  }

  if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
    return false;
  }

  int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);

  if (AuthStatus==1) {
    *Authentic = true;
    //EVP_MD_CTX_free(m_RSAVerifyCtx);
    return true;
  } else if(AuthStatus==0){
    *Authentic = false;
    //EVP_MD_CTX_free(m_RSAVerifyCtx);
    return true;
  } else{
    *Authentic = false;
    //EVP_MD_CTX_free(m_RSAVerifyCtx);
    return false;
  }
}



int main(void){



  unsigned char* pubout;
  size_t publen;
  Base64Decode((const char *) b64pub, &pubout, &publen);
  printf("%.*s\n", (int)publen, pubout);

  unsigned char* priout;
  size_t prilen;
  Base64Decode((const char *) b64pri, &priout, &prilen);
  printf("%.*s\n", (int)prilen, priout);

  //BIO *prkeybio = NULL;
  //prkeybio = BIO_new_mem_buf((void*) b64pri, prilen);

  //RSA *srsa = NULL;
  //srsa = PEM_read_bio_RSAPrivateKey(prkeybio, &srsa, NULL, NULL);

  //printf("GOTHERE \n");


const char* decodedexample = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAs1l0PEtgQRtk5mkclhMFTtkLGWUG/11ZiMG+wA7FCIljrs0u6rzT\n8XSILc0Gr7JEAQO+2r8r23HQnqQMRrAL8TnTHXWrClat7SFoOQlIQ3Oy0C2sxmk+\nKFhKFZy9fxCVcy4H+Qu6OF4HY6Aym08/oPBhIEnw7W29eH7VrkCrRDa9MwYZibD1\nyz8GM7OwrltU5wWt8GL0SMcMRe0rAfziwS+8u+rGFGVrPZ8f2ZhZrq0bfCIWdtp6\n58K1LqKomLayIDowy+9Lk79nI17xV7YnJammzZgSaNQXy+Az9c1rszT7RHK4rhUN\n0J8IDxuZVpzWjIEJQXY92yZQ0x7loNq8uwIDAQAB\n-----END RSA PUBLIC KEY-----\n";

  //printf("%s\n", decodedexample);


  BIO *pbkeybio = NULL;
  pbkeybio = BIO_new_mem_buf((void*) pubout, -1);

  RSA *prsa = NULL;
  //prsa = PEM_read_bio_RSA_PUBKEY(pbkeybio, &prsa, NULL, NULL);
  prsa = PEM_read_bio_RSAPublicKey(pbkeybio, &prsa, NULL, NULL);


  unsigned char* sigout;
  size_t siglen;
  Base64Decode((const char *) b64sig, &sigout, &siglen);

  printf("%s\n\n", message);


  bool authentic;
  bool result = RSAVerifySignature(prsa, sigout, siglen, message, strlen(message), &authentic);
  printf("VERIFICATION RESULT: %d\n", result & authentic);


  return 0;
}