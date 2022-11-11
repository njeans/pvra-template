/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "enclave.h"
#include <enclave_t.h>
#include <stdio.h>
#include <stdarg.h>

void print(const char *const str) { ocall_print_string(str); }

void printint(const int * num) { ocall_print_int(num); }

int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}


void print_hexstring(const void *vsrc, size_t len) {
  const unsigned char *sp = (const unsigned char *)vsrc;
  size_t i;
  for (i = 0; i < len; ++i) {
    printf("%02x", sp[i]);
  }
  printf("\n");
}

void print_hexstring_n(const void *vsrc, size_t len) {
  const unsigned char *sp = (const unsigned char *)vsrc;
  size_t i;
  for (i = 0; i < len; ++i) {
    printf("%02x", sp[i]);
  }
}

void print_hexstring_trunc_n(const void *vsrc, size_t len) {
  size_t len_t;
  if (len < 6) {
    len_t = len/2;
  } else {
    len_t = 3;
  }
  print_hexstring_n(vsrc, len_t);
  printf("...");
  print_hexstring_n(vsrc + len - len_t, len_t);
}

void ocallrdtsc(void) {
    ocall_rdtsc();
}

int sprintf(char * out, const char* fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    memcpy(out, &buf, (int)strnlen(buf, BUFSIZ - 1) + 1);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}
