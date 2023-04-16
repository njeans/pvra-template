#include <netdb.h>
#include <sys/socket.h>


#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/types.h>

#include "enclave_t.h"

#include "constants.h"
#include "ca_bundle.h"

static char *ciphers_list = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256\0";

#define _XOPEN_SOURCE 700

//todo add link to wolfssl example
#if defined(XMALLOC_USER) || defined(XMALLOC_OVERRIDE)
    #warning verification of heap hint pointers needed when overriding default malloc/free
#endif

#if defined(WOLFSSL_STATIC_MEMORY)
/* check on heap hint when used, aborts if pointer is not in Enclave.
 * In the default case where wolfSSL_Malloc is used the heap hint pointer is not
 * used.*/
static void checkHeapHint(WOLFSSL_CTX* ctx, WOLFSSL* ssl)
{
    WOLFSSL_HEAP_HINT* heap;
    if ((heap = (WOLFSSL_HEAP_HINT*)wolfSSL_CTX_GetHeap(ctx, ssl)) != NULL) {
        if(sgx_is_within_enclave(heap, sizeof(WOLFSSL_HEAP_HINT)) != 1)
            abort();
        if(sgx_is_within_enclave(heap->memory, sizeof(WOLFSSL_HEAP)) != 1)
            abort();
    }
}
#endif /* WOLFSSL_STATIC_MEMORY */


int communicate_with_server(char * server_name, char * server_port, char * send_buff, char * out_buff, size_t out_buff_size) {
    int err, ret, socketfd;
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_CTX* ctx = NULL;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM; 
    hints.ai_flags = AI_CANONNAME;
    hints.ai_protocol = 0;
    
    err = getaddrinfo(server_name, server_port, &hints, &result);
    if (err != 0) {
        printf_stderr("%s getaddrinfo err %d\n", server_name, err);
        ret = 0;
        goto cleanup;
    }

    socketfd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (socketfd == -1) {
        printf_stderr("%s socket() failed\n", server_name);
        ret = 0;
        goto cleanup;
    }

    // if(DEBUGPRINT) printf("%s socket success\n", server_name);

    err = connect(socketfd, result->ai_addr, result->ai_addrlen);
    if (err != 0) {
        printf_stderr("%s connect failed\n", server_name);
        ret = err;
        goto cleanup;
    }
    // if(DEBUGPRINT) printf("%s connect success\n", server_name);
    // if(DEBUGPRINT) wolfSSL_Debugging_ON();

    err = wolfSSL_Init();
    if (err != SSL_SUCCESS) {
        printf_stderr("%s wolfSSL_Init err %d\n", server_name, err);
        ret = -1;
        goto cleanup;
    }
    // if(DEBUGPRINT) printf("%s wolfSSL_Init success\n", server_name);

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());

    if (ctx == NULL) {
        printf_stderr("%s wolfSSL_CTX_new err\n", server_name);
        ret = -1;
        goto cleanup;
    }
    // if(DEBUGPRINT) printf("%s wolfSSL_CTX_new success\n", server_name);


    err = wolfSSL_CTX_set_cipher_list(ctx, ciphers_list);
    if (err != SSL_SUCCESS) {
        printf_stderr("%s wolfSSL_Init err %d\n", server_name, err);
        ret = -1;
        goto cleanup;
    }

    err = wolfSSL_CTX_load_verify_buffer(ctx, default_ca_bundle, strlen(default_ca_bundle), SSL_FILETYPE_PEM);
    if (err != SSL_SUCCESS) {
        printf_stderr("%s wolfSSL_CTX_load_verify_buffer err %d\n", server_name, err);
        ret = -1;
        goto cleanup;
    }
    // if(DEBUGPRINT) printf("%s wolfSSL_CTX_load_verify_buffer success\n", server_name);

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        printf_stderr("%s wolfSSL_new err\n", server_name);
        ret = -1;
        goto cleanup;
    }
    // if(DEBUGPRINT) printf("%s wolfSSL_new success\n", server_name);

    err = wolfSSL_set_fd(ssl, socketfd);
    if (err != SSL_SUCCESS) {
        printf_stderr("%s wolfSSL_set_fd err %d\n", server_name, err);
        ret = -1;
        goto cleanup;
    }
    // if(DEBUGPRINT) printf("%s wolfSSL_set_fd success\n", server_name);

    err = wolfSSL_connect(ssl);
    if (err != SSL_SUCCESS) {
        printf_stderr("%s wolfSSL_connect err %d\n", server_name, err);
        ret = -1;
        goto cleanup;
    }
    // if(DEBUGPRINT) printf("%s wolfSSL_connect success\n", server_name);

    err = wolfSSL_write(ssl, send_buff, strlen(send_buff) + 1);
    if (err != strlen(send_buff) + 1) {
        printf_stderr("%s wolfSSL_write partial write %d != %d\n", server_name, err, strlen(send_buff) + 1);
        ret = -1;
        goto cleanup;
    }
    if(DEBUGPRINT) printf("%s wolfSSL_write success\n", server_name);

    err = wolfSSL_read(ssl, out_buff, out_buff_size);
    if (err < 0) {
        printf_stderr("%s wolfSSL_read err %d\n", server_name, err);
        ret = -1;
    }
    ret = 0;
    goto cleanup;

cleanup:
    if (result != NULL) {
        freeaddrinfo(result);
        result = NULL;
    }
    if (ssl != NULL) {
        wolfSSL_free(ssl);
        ssl = NULL;
    }
    if (ctx != NULL) {
        wolfSSL_CTX_free(ctx);
        ctx = NULL;
    }
    wolfSSL_Cleanup();
    return ret;
}

#define EPOCH_YEAR 1970
#define TM_YEAR_BASE 1900
#define TYPE_SIGNED(t) (! ((t) 0 < (t) -1))
#define SHR(a, b)                                               \
  ((-1 >> 1 == -1                                               \
    && (long int) -1 >> 1 == -1                                 \
    && ((time_t) -1 >> 1 == -1 || ! TYPE_SIGNED (time_t)))      \
   ? (a) >> (b)                                                 \
   : (a) / (1 << (b)) - ((a) % (1 << (b)) < 0))

const unsigned short int __mon_yday[2][13] =
{
// Normal years.  
{ 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 },
// Leap years.  
{ 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366 }
};

// Return 1 if YEAR + TM_YEAR_BASE is a leap year.  
static int
leapyear (long int year)
{
  // Don't add YEAR to TM_YEAR_BASE, as that might overflow.
  //   Also, work even if YEAR is negative.  
  return
    ((year & 3) == 0
     && (year % 100 != 0
	 || ((year / 100) & 3) == (- (TM_YEAR_BASE / 100) & 3)));
}

static time_t
ydhms_diff (long int year1, long int yday1, int hour1, int min1, int sec1,
	    int year0, int yday0, int hour0, int min0, int sec0)
{
  // Compute intervening leap days correctly even if year is negative.
  //   Take care to avoid integer overflow here.  
  int a4 = SHR (year1, 2) + SHR (TM_YEAR_BASE, 2) - ! (year1 & 3);
  int b4 = SHR (year0, 2) + SHR (TM_YEAR_BASE, 2) - ! (year0 & 3);
  int a100 = a4 / 25 - (a4 % 25 < 0);
  int b100 = b4 / 25 - (b4 % 25 < 0);
  int a400 = SHR (a100, 2);
  int b400 = SHR (b100, 2);
  int intervening_leap_days = (a4 - b4) - (a100 - b100) + (a400 - b400);

  // Compute the desired time in time_t precision.  Overflow might
  //   occur here.  
  time_t tyear1 = year1;
  time_t years = tyear1 - year0;
  time_t days = 365 * years + yday1 - yday0 + intervening_leap_days;
  time_t hours = 24 * days + hour1 - hour0;
  time_t minutes = 60 * hours + min1 - min0;
  time_t seconds = 60 * minutes + sec1 - sec0;
  return seconds;
}

//mktime not available in SGX. Adapted from glibc implementation:
//https://codebrowser.dev/glibc/glibc/time/mktime.c.html
time_t mktime(struct tm * tp) {
    int sec = tp->tm_sec;
    int min = tp->tm_min;
    int hour = tp->tm_hour;
    int mday = tp->tm_mday;
    int mon = tp->tm_mon - 1;
    int year_requested = tp->tm_year;

    int mon_remainder = mon % 12;
    int negative_mon_remainder = mon_remainder < 0;
    int mon_years = mon / 12 - negative_mon_remainder;
    long int lyear_requested = year_requested;
    long int year = lyear_requested + mon_years;

    int mon_yday = ((__mon_yday[leapyear (year)]
            [mon_remainder + 12 * negative_mon_remainder])
            - 1);
    long int lmday = mday;
    long int yday = mon_yday + lmday;

    //ignore leap second
    if (sec < 0)
	    sec = 0;
    if (59 < sec)
	    sec = 59;

    time_t t0 = ydhms_diff(year, yday, hour, min, sec,
		   EPOCH_YEAR - TM_YEAR_BASE, 0, 0, 0, 0);
    return t0;
}

//parse time in format "YYYY-MM-DD HH:MM:SS"
int parse_time(char * datetime, time_t * curr_time) {
    int res;
    struct tm tm;
    memset(&tm, 0, sizeof(struct tm));
    char tmp[5];
    memcpy(tmp, datetime, 4);
    tmp[4] = 0;
    res = atoi(tmp);
    if (res == 0) return -1;
    tm.tm_year = res - TM_YEAR_BASE;
    memcpy(tmp, datetime + 5, 2);
    tmp[2] = 0;
    res = atoi(tmp);
    if (res == 0) return -1;
    tm.tm_mon = res;
    memcpy(tmp, datetime + 8, 2);
    tmp[2] = 0;
    res = atoi(tmp);
    if (res == 0) return -1;
    tm.tm_mday = res;
    memcpy(tmp, datetime + 11, 2);
    tmp[2] = 0;
    res = atoi(tmp);
    if (res == 0) return -1;
    tm.tm_hour = res;
    memcpy(tmp, datetime + 14, 2);
    tmp[2] = 0;
    res = atoi(tmp);
    if (res == 0) return -1;    
    tm.tm_min = res;
    memcpy(tmp, datetime + 17, 2);
    tmp[2] = 0;
    res = atoi(tmp);
    if (res == 0) return -1;
    tm.tm_sec = res;
    if(DEBUGPRINT) printf("parse_time year %d month %d day %d hour %d min %d sec %d\n",
                            tm.tm_year,
                            tm.tm_mon,
                            tm.tm_mday,
                            tm.tm_hour,
                            tm.tm_min,
                            tm.tm_sec);
    *curr_time = mktime(&tm);
    if(DEBUGPRINT) printf("unix timestamp %ld\n", *curr_time);
    return 0;
}

int worldtimeapi(char * datetime) {
    int ret;
    char buff[1024] = { 0 };
    char* server_name = "www.worldtimeapi.org";
    char* server_port = "443";
    char* send_buff = "GET api/timezone/Etc/UTC HTTP/1.1\r\nHost: www.worldtimeapi.org\n\n\r\n\0";
    ret = communicate_with_server(server_name, server_port, send_buff, buff, sizeof(buff)-1);
    if (ret == 0) {
        if(DEBUGPRINT) printf("worldtimeapi() communicate_with_server() success\n");
    } else {
        return -1;
    }
    datetime = strstr(buff, "dateTime") + 11;
    if (datetime == NULL) {
        printf_stderr("worldtimeapi() dateTime not in response:\n%s\n", buff);
        return -1;
    }
    return 0;
}

uint64_t timeapiio(char * datetime) {
    int ret;
    char buff[1024] = { 0 };
    char* server_name = "www.timeapi.io\0";
    char* server_port = "443\0";
    char* send_buff = "GET /api/Time/current/zone?timeZone=UTC HTTP/1.1\r\nHost: www.timeapi.io\n\n\r\n\0";
    ret = communicate_with_server(server_name, server_port, send_buff, buff, sizeof(buff)-1);
    if (ret == 0){
        if(DEBUGPRINT) printf("timeapiio() communicate_with_server() success\n");
    } else {
        return -1;
    }
    datetime = strstr(buff, "dateTime") + 11;
    if (datetime == NULL) {
        printf_stderr("timeapiio() dateTime not in response:\n%s\n", buff);
        return -1;
    }
    return 0;
}


int get_timestamp(time_t *curr_time) {
    char * datetime = NULL;
    int res = worldtimeapi(datetime);
    if (res == -1){
        res = timeapiio(datetime);
        if (res == -1) {
            return -1;
        }
    }
    

    return parse_time(datetime, curr_time);
}

int get_timestamp_str(char *datetime) {
    int res = worldtimeapi(datetime);
    if (res == -1){
        res = timeapiio(datetime);
    }
    return res;
}