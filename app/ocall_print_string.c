/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>

/* Ensure that ocall_print_string has extern C linkage */
#include <enclave_u.h>

#include "app.h"

void ocall_print_string(const char *str) {
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  printf("%s", str);
}

unsigned cycles_low, cycles_high;

static __inline__ unsigned long long rdtsc(void)
{
__asm__ __volatile__("lfence" ::: "memory");
    __asm__ __volatile__ ("RDTSC\n\t"
            "mov %%edx, %0\n\t"
            "mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::
            "%rax", "rbx", "rcx", "rdx");
__asm__ __volatile__("lfence" ::: "memory");
}


void ocall_rdtsc(void) {
  /* uint64_t c;
  __asm {
      cpuid       // serialize processor
      rdtsc       // read time stamp counter
      mov dword ptr [c + 0], eax
      mov dword ptr [c + 4], edx
  }*/
  rdtsc();
  uint64_t start = ( ((uint64_t)cycles_high << 32) | cycles_low );
  tsc_dump[tsc_idx] = start;
  //printf("RDTSC OCALL: %lu\n", start);
  //printf("RDTSC OC[%d]: %lu\n", tsc_idx, tsc_dump[tsc_idx]);
  tsc_idx++;

  //clock_gettime(start);
}

// void ocall_print_int(const int num) {
//    /* Proxy/Bridge will check the length and null-terminate
//     * the input string to prevent buffer overflow.
//     */
//    printf("%d", num);
//}


void ocallbuf(const int size) {
  pub_enckey_buffer_size = size;
  printf("%d", size);
  if (pub_enckey_buffer != NULL) {
    free(pub_enckey_buffer);
    pub_enckey_buffer = NULL;
  }
  pub_enckey_buffer = calloc(pub_enckey_buffer_size, 1);
}
