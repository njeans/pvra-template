/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <getopt.h>
#include <stdio.h>

#include <openssl/evp.h>

#include "app.h"

static struct option long_options[] = {

  {"initPVRA", no_argument, 0, 0},
  {"commandPVRA", no_argument, 0, 0},
  {"restartPVRA", no_argument, 0, 0},

  {"enclave-path", required_argument, 0, 0},
  {"sealedState", required_argument, 0, 0},
  {"quotefile", required_argument, 0, 0},
  {"signature", required_argument, 0, 0},
  {"signedFT", required_argument, 0, 0},
  {"FT", required_argument, 0, 0},
  {"eCMD", required_argument, 0, 0},
  {"eAESkey", required_argument, 0, 0},
  {"cResponse", required_argument, 0, 0},
  {"cRsig", required_argument, 0, 0},
  {"sealedOut", required_argument, 0, 0},

  {0, 0, 0, 0}

};

/**
 * main()
 */
int main(int argc, char **argv) {
  bool opt_initPVRA = false;
  bool opt_commandPVRA = false;
  bool opt_restartPVRA = false;

  const char *opt_enclave_path = NULL;
  const char *opt_sealedstate_file = NULL;
  const char *opt_quote_file = NULL;
  const char *opt_signature_file = NULL;
  const char *opt_signedFT_file = NULL;
  const char *opt_FT_file = NULL;
  const char *opt_eCMD_file = NULL;
  const char *opt_eAESkey_file = NULL;
  const char *opt_cResponse_file = NULL;
  const char *opt_cRsig_file = NULL;
  const char *opt_sealedout_file = NULL;


  int option_index = -1;

  while (getopt_long_only(argc, argv, "", long_options, &option_index) != -1) {
    switch (option_index) {
    case -1:
      break;
    case 0:
      opt_initPVRA = true;
      break;
    case 1:
      opt_commandPVRA = true;
      break;
    case 2:
      opt_restartPVRA = true;
      break;
    case 3:
      opt_enclave_path = optarg;
      break;
    case 4:
      opt_sealedstate_file = optarg;
      break;
    case 5:
      opt_quote_file = optarg;
      break;
    case 6:
      opt_signature_file = optarg;
      break;
    case 7:
      opt_signedFT_file = optarg;
      break;
    case 8:
      opt_FT_file = optarg;
      break;
    case 9:
      opt_eCMD_file = optarg;
      break;
    case 10:
      opt_eAESkey_file = optarg;
      break;
    case 11:
      opt_cResponse_file = optarg;
      break;
    case 12:
      opt_cRsig_file = optarg;
      break;
    case 13:
      opt_sealedout_file = optarg;
      break;
    }
  }


  if (!opt_initPVRA && !opt_commandPVRA && !opt_restartPVRA) {
    fprintf(stderr, "Error: Must specify either --initPVRA OR --commandPVRA OR --restartPVRA\n");
    return EXIT_FAILURE;
  }

  if (opt_initPVRA && (!opt_enclave_path) && (!opt_sealedstate_file) && (!opt_quote_file) && (!opt_signature_file)) {
    fprintf(stderr, "Error Usage:\n");
    fprintf(stderr, "  %s --initPVRA --enclave-path /path/to/enclave.signed.so \
      --sealedState sealedState.bin \
      --quotefile quote.bin \
      --signature enckey.sig\n", argv[0]);
    return EXIT_FAILURE;
  }

  if (opt_commandPVRA && (!opt_enclave_path) && (!opt_sealedstate_file) && (!opt_signedFT_file) && (!opt_FT_file) && (!opt_eCMD_file) && (!opt_eAESkey_file) && (!opt_cResponse_file) && (!opt_cRsig_file)) {
    fprintf(stderr, "Error Usage:\n");
    fprintf(stderr, "  %s --commandPVRA --enclave-path /path/to/enclave.signed.so \
      --sealedState sealedState.bin \
      --signedFT signedFT.bin \
      --FT FT.txt \
      --eCMD eCMD.bin \
      --eAESkey eAESkey.bin \
      --cResponse cResponse.txt \
      --cRsig cResponse.sig \
      --sealedOut sealedOut.bin\n", argv[0]);
    return EXIT_FAILURE;
  }

  if (opt_restartPVRA && (!opt_enclave_path)) {
    fprintf(stderr, "Error Usage:\n");
    fprintf(stderr, "  %s --restartPVRA --enclave-path /path/to/enclave.signed.so\n", argv[0]);
    return EXIT_FAILURE;
  }


  OpenSSL_add_all_algorithms(); /* Init OpenSSL lib */


  bool success_status =
    create_enclave(opt_enclave_path) && 
    enclave_get_buffer_sizes() &&
    allocate_buffers() && 

    (opt_initPVRA ? initPVRA() : true) &&
    (opt_initPVRA ? save_seal(opt_sealedstate_file) : true) &&
    (opt_initPVRA ? save_quote(opt_quote_file) : true) &&
    (opt_initPVRA ? save_signature(opt_signature_file) : true) &&
    (opt_initPVRA ? save_message() : true) &&

    (opt_commandPVRA ? load_seal(opt_sealedstate_file) : true) &&
    (opt_commandPVRA ? load_ft(opt_FT_file) : true) &&
    (opt_commandPVRA ? load_sig(opt_signedFT_file) : true) &&
    (opt_commandPVRA ? load_cmd(opt_eCMD_file) : true) &&
    (opt_commandPVRA ? load_key(opt_eAESkey_file) : true) &&
    (opt_commandPVRA ? format_sig(opt_signedFT_file) : true) &&      
    (opt_commandPVRA ? commandPVRA() : true) &&
    (opt_commandPVRA ? save_cResponse(opt_cResponse_file) : true) &&
    (opt_commandPVRA ? save_cRsig(opt_cRsig_file) : true) &&
    (opt_commandPVRA ? save_sealO(opt_sealedout_file) : true);

  if (sgx_lasterr != SGX_SUCCESS) {
    fprintf(stderr, "[agPVRA]: ERROR: %s\n", decode_sgx_status(sgx_lasterr));
  }

  destroy_enclave();
  cleanup_buffers();

  return success_status ? EXIT_SUCCESS : EXIT_FAILURE;
}
