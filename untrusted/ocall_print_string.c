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


void ocall_allocate_seal(size_t init_sealsize) {
  sealed_state_buffer_size = init_sealsize;
  free(sealed_state_buffer);
  sealed_state_buffer = calloc(sealed_state_buffer_size, 1);

  sealed_out_buffer_size = init_sealsize;
  free(sealed_out_buffer);
  sealed_out_buffer = calloc(sealed_out_buffer_size, 1);
  printf("DONE ALLOCATING %p %p\n", sealed_out_buffer, sealed_state_buffer);
}


// void ocall_print_int(const int num) {
//    /* Proxy/Bridge will check the length and null-terminate
//     * the input string to prevent buffer overflow.
//     */
//    printf("%d", num);
//}

//
//void ocallbuf(const int size) {
//}
