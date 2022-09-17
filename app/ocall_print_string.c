/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>

/* Ensure that ocall_print_string has extern C linkage */
#include <enclave_u.h>

void ocall_print_string(const char *str) {
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  printf("%s", str);
}

unsigned cycles_low, cycles_high;

static __inline__ unsigned long long rdtsc(void)
{
    __asm__ __volatile__ ("RDTSC\n\t"
            "mov %%edx, %0\n\t"
            "mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::
            "%rax", "rbx", "rcx", "rdx");
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
  printf("RDTSC OCALL: %lu\n", start);
  clock_gettime(start);
}

// void ocall_print_int(const int num) {
//    /* Proxy/Bridge will check the length and null-terminate
//     * the input string to prevent buffer overflow.
//     */
//    printf("%d", num);
//}
