#include <stdio.h>
#include <netdb.h>

/* Ensure that ocall_print_string has extern C linkage */
#include <enclave_u.h>

#include "app.h"

void ocall_print_string(const char *str) {
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  printf("%s", str);
}

void ocall_print_stderr(const char *str) {
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  fprintf(stderr, "%s", str);
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
  rdtsc();
  tsc_dump[tsc_idx] = ( ((uint64_t)cycles_high << 32) | cycles_low );
  tsc_idx++;
}