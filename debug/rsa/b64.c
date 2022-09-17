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

const char* b64pubworks = "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJDZ0tDQVFFQXMxbDBQ\nRXRnUVJ0azVta2NsaE1GVHRrTEdXVUcvMTFaaU1HK3dBN0ZDSWxqcnMwdTZyelQK\nOFhTSUxjMEdyN0pFQVFPKzJyOHIyM0hRbnFRTVJyQUw4VG5USFhXckNsYXQ3U0Zv\nT1FsSVEzT3kwQzJzeG1rKwpLRmhLRlp5OWZ4Q1ZjeTRIK1F1Nk9GNEhZNkF5bTA4\nL29QQmhJRW53N1cyOWVIN1Zya0NyUkRhOU13WVppYkQxCnl6OEdNN093cmx0VTV3\nV3Q4R0wwU01jTVJlMHJBZnppd1MrOHUrckdGR1ZyUFo4ZjJaaFpycTBiZkNJV2R0\ncDYKNThLMUxxS29tTGF5SURvd3krOUxrNzluSTE3eFY3WW5KYW1telpnU2FOUVh5\nK0F6OWMxcnN6VDdSSEs0cmhVTgowSjhJRHh1WlZweldqSUVKUVhZOTJ5WlEweDds\nb05xOHV3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K\n";

const char* b64pub = "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJDZ0tDQVFFQXRsS1RW\nN09kU2EzK3hIQndCKzhhTm9TdkZESC9qdUVMQjFWOU9kWFZZQVlhQ0NsaEJOSncK\nbkF2NEJQRUdUTmU4MHBwNEpBSE9JdUk1aURJUW1QOGgrTzhZTzVMVEttaEhhV3Nj\nbWU4TTJoNk8wbit4U3l4bwpzbUsyTk43Y3NBRzBja0Y0MTBmVHN5cS80TU4rRURH\nYTBoVU04SHlEMWZGVWUraStGSGJ6RVVmT09mRkxLaHdPCjhtVUowTTBFMmRRMFhh\nRFUyRHJDZ0lBWklFS044Q3RkeVBhcHIwTHhqNTVzRmVpRkt2T2RhanlnbGtvbmtl\nV2oKVHRCczBqcFlpMzhRVUJZK1gwSEdYVld2Z29tTyttRzJCZG1rZTZHTnpNYmRP\nQTFiRExFVlpUZ21EWUZUTmgvbApCYXViRzFlZ1h5eDNkQ1NuVk44VFl4cnVuN0Rt\nVFNndXJRSURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K\n";

const char* b64priworks = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVB\nczFsMFBFdGdRUnRrNW1rY2xoTUZUdGtMR1dVRy8xMVppTUcrd0E3RkNJbGpyczB1\nCjZyelQ4WFNJTGMwR3I3SkVBUU8rMnI4cjIzSFFucVFNUnJBTDhUblRIWFdyQ2xh\ndDdTRm9PUWxJUTNPeTBDMnMKeG1rK0tGaEtGWnk5ZnhDVmN5NEgrUXU2T0Y0SFk2\nQXltMDgvb1BCaElFbnc3VzI5ZUg3VnJrQ3JSRGE5TXdZWgppYkQxeXo4R003T3dy\nbHRVNXdXdDhHTDBTTWNNUmUwckFmeml3Uys4dStyR0ZHVnJQWjhmMlpoWnJxMGJm\nQ0lXCmR0cDY1OEsxTHFLb21MYXlJRG93eSs5TGs3OW5JMTd4VjdZbkphbW16WmdT\nYU5RWHkrQXo5YzFyc3pUN1JISzQKcmhVTjBKOElEeHVaVnB6V2pJRUpRWFk5Mnla\nUTB4N2xvTnE4dXdJREFRQUJBb0lCQVFDS1V5bjAvdVdrRVc3Rwp6cmIvZ0hnTmto\nU2ZaMjM0TXBWRmhyaUtCRm91OVZmdWo4M3B1ZTExUXIxdEpiNU1jQjlHOFE2WVEr\nMmRlTERBClNpSTF1cjNiTlJBQW5xcG1kT2Y4QmxJTiszekNtVStHaEZQSFM1Qm5L\nWUVxSGhPQkZ0ZE5XR2xKeWFPOHFiamwKTzc4TVRoanpGYkt6WnBQdGEwQkEyUUlS\nUFV0YWRkcjd3K1R0emNPQlVObW9LVXVycU4rWHFwUFdVNW1iZlV1SQovVmxoeDVD\nQUI5VlFYVDVqalR4Z0xHUzZmT3ZranRGOEtsMEZaS1RsaUdzb1puczlkNWtDREpy\nK21FbnovU1c1CkkrL2tXamM1WXdVd2pHT3BwTHdSYkdLM1ptcWVxbnZhUXkrcFpJ\nR3FhMytmNjJuVjFVYjF2NEpxSnFROHROY0sKUUo0MGRCRFJBb0dCQU5aWHFld1Qy\neHVrV2p4WDRvZGJ2UVNoWS93VkxLbG9qZmgraXp1UmdIWlpuNGxsbzZ0NQpZQnh5\nOHV1RUNGUUVMVVhDekJOeHdkYUwrdTZEV3RlU0ppV2lMQWVFUEU4YXVuL2QwRHlS\nVnp2YWtLeXk4cGk1Ck0rNDFNSWI5K3NjTTd5aXJqOEpFSlJUenJ0MlNnV0ZLM3dI\nSC9HNEJFVmhzV2g3NTUxUEZLMGNYQW9HQkFOWTAKd2ZHckJYR0tUOVM0N1RYbUNl\ndjlBMS84YTBlV28zWUZ0dDVMZFZUYkU3NTd3TysydE15K1ZNaURONjZMdVFGQgpU\nYk1lMjJOZUVyV3l2TktvSDhhakNpZWtwbW15VGk1TUtkemxXeVNiZ044Rk1jbGFm\nd3B6T0pCQW1NT0V0Vi85ClV3WTdwUzUyaTE1Q3p4c1BNenloRXFqL3M5ZTdKY0tT\nVis1TEl6MzlBb0dBVVRBemRQQ3dkZS96SGhoTC9lbUoKMTA4cWlEbWRDUzVKV0c3\nV1htSG12dTJEdUk5L1IxeGFRMnhuQno2anlPOHNGdGlLWkhNYWNTSGtrcU8rclJq\nMgp5aHA3Z3YxYnVycnRHYkh6Um4zbkJRenM3LzE0VnRFUUVwS2pKdjdkRnJpWGZs\nZzl3OS84Qzh1aDJOdTlsaFMrCkUvYWtieWFJWTIzblZRUmoweDlFSFZFQ2dZRUFu\nRHJZWldHZDA4VFVHc3RSdjJqclBhSklydDVVaEY4YkUzNXgKZE1wR1prQnVzeFJo\na0xTS1EzWmlNZWg2V1NUeEp6Z3c2bjZMOW5wclhQaGkvYVcvbjBuVW96dFVZR3k2\nMXN1WQpFTk43V1VUTmhsdXNoellveUQ5bk50YldWR3ZiT1lweTNtM3NPT29mRmYz\nV1BkOGxPSWdtS3Zwc2VlQzJWcVlUCjJlb1ZaeVVDZ1lBWGFEOUFlc29yMGp1R2JW\nZWZQZVJFbUJrcDgySk9TeHhuQlNjYU1ZVncvb1huNzNaNkZSdWYKVkRtOTdEOVRO\neGVKc1p1UjBRRkI0b0lnNjBrVkN1RVEzaEY2UTlXa3dpZ2RmajczS2hMdEZOUm1k\nUUE0WHJ5bgp6MFdzYzllS2lsbU9vV3Y4WE91QXJPa0M0elMwWDBTQXZ5VDVLT1lP\nVWEzWWhpOFA1OUx5Wnc9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=\n";
const char* b64pri = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVB\ndGxLVFY3T2RTYTMreEhCd0IrOGFOb1N2RkRIL2p1RUxCMVY5T2RYVllBWWFDQ2xo\nCkJOSnduQXY0QlBFR1ROZTgwcHA0SkFIT0l1STVpRElRbVA4aCtPOFlPNUxUS21o\nSGFXc2NtZThNMmg2TzBuK3gKU3l4b3NtSzJOTjdjc0FHMGNrRjQxMGZUc3lxLzRN\nTitFREdhMGhVTThIeUQxZkZVZStpK0ZIYnpFVWZPT2ZGTApLaHdPOG1VSjBNMEUy\nZFEwWGFEVTJEckNnSUFaSUVLTjhDdGR5UGFwcjBMeGo1NXNGZWlGS3ZPZGFqeWds\na29uCmtlV2pUdEJzMGpwWWkzOFFVQlkrWDBIR1hWV3Znb21PK21HMkJkbWtlNkdO\nek1iZE9BMWJETEVWWlRnbURZRlQKTmgvbEJhdWJHMWVnWHl4M2RDU25WTjhUWXhy\ndW43RG1UU2d1clFJREFRQUJBb0lCQUhhRDNPVndpemkrMHRJTQpxTFp2bGFHRXhH\nNGpSaFV4Y2tMVkxtNnU4bUhWOVl3Q29kOUprQXZQdCt3MlpMc0VyZWhVb3UzOUFt\nc29sTzlVClkvZWdPUXdoRjZaNS9hd2VWdlZPdkN2UCtaRzd0V2xkdWZpOHFGMzB6\ncTQxaEUwZy9wUWF2UnRyeEZBOTVMYU4KUFYvM2JzVkxDN3N6cFZzbjRad2VJWmta\nN1V6NFAyWm5yZmhFY0F3bkh4SmowUVpwYjlOZnRiUGJUekVLeFVvagpsYkw3RGI2\nK3VJTnhVWTNPYjVCMkxFWlpXNlFweHgzellyc1BtTStyTmdEVGEwU3ZNRExzdWg0\nZXdBZzFDanNaCkFBSnRUVGRwU3FEM0VHNFRkL254ejBVSG5yZFNMOE8vNXVGM0tT\nalRFNFAxN1lXc09NbEtUTTQ3dkdVQnNYanoKc1ZQNTFYMENnWUVBNm1RUk5nZFlX\nTjc2L1ROS25kQW8wU01YaXI1TEl4VnQ1OEpDdkdzSkZsak5GblhTQ1dOdQorYkcz\neWxla0cvenJrMjQzSGdXOEtkaCs4Y2JWc21jaXRLcnhiZHZTV2ozOVlTVXlUVHd5\nNDJRRHQ1dkZWZTU4ClR3Q1pmUlUwNHVCcnh1OWwzaWI3MkF4ZTFyOTdzK3E4QjhS\nV0N5UW50NXQ1UzFsSnpBZFNFTU1DZ1lFQXh5R2cKbjJXYjR0UkVuMURrWXdXd1J4\nZ3dzZFJkN0JVR1hWbHpkNmVEcVJ1UHQvLy82TFp5T2JOalIvckRkRDdmNXMwWApZ\nTDB3Z3haZjNtYTFDTDI4ODR2VHlSbFRJVURqWFE1d0ltdU55Z0V1YkZwbGk1T0ph\ndi83aGtsbzd1Y3RJMUhvCnN3bE1zWWY3WitCVEJKN1VlYm1odFZ3ZUo2dE5vend1\nRmM5V3k4OENnWUJGWG9CSmdUc0FjbDNOK2hRblNLZ0wKM1ZybVVSTmp1ci9nUzNu\nODBhREs0RlV5UklSNUN0aVpSYU9qV3ZUUzQ3UEUybVd0bVB6clZZdWNlc0JjSUhJ\nQgpEbWFOb1BWTWgvUXBnQnkzQnczNGhtMGpOaExkTDh2U2hkYm5VaE5vNGdxRHdl\nNWdKU0Y3KzQxRitUM2ZMYVdnCmx0YndUUzhFQkJ1TjFVc2wrelNxaVFLQmdRQ1Vp\nb0lkeFJiMnFtOFNCSzZKS3pvbW5tWGNrVlVLZ1ZpQkUvUHQKUXRrVXNZbVFzUGM5\ncWJNbFZhcHVqQ0YydWx3Yzk4cERrSHo2bkJzaGRLNEFla0RUeis5SXFJcDVXTVVC\ncW41OQpQb3ZETHdScE1UbGtWOGIvT1Rwd0hweVc4WDJiUmtOMklpN0NrM1EzTlgv\nWUIzN3AyazVGVWhUd2RIbHlsYmF1CjhENkh3d0tCZ0g5M21yVEQ0NVB5WWJ4NUx5\nOGdBalN0Z3dINzRTUnNmVWlQSWRGblAwT0tyZWgzVTFYN0RSYk0KSHJ6OHpWb2ZL\nMzgwRlhpNHplOXV5L0dRS0t2TjNKckJJcFVlaU9UVnkzVjB2ZFF1Qmlremc5RWxI\ncnBVbnJHLwpVbzdtelZKQWVGNWEzb25XU283WkNQRnp3L2IxQmIxaXg3UlVXM2tn\nVXBkYWhVWktLNnBDCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg==\n";

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