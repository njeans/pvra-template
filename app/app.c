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
    
    
    
    {"keygen", no_argument, 0, 0},
    {"quote", no_argument, 0, 0},
    {"sign", no_argument, 0, 0},
    {"call_vsc", no_argument, 0, 0},
    {"keygen_vsc", no_argument, 0, 0},
    {"keygen_ecdsa", no_argument, 0, 0},
    {"encrypt_aes", no_argument, 0, 0},
    {"decrypt_aes", no_argument, 0, 0},
    {"create_student", no_argument, 0, 0},
    {"load_student", no_argument, 0, 0},
    {"update_student", no_argument, 0, 0},
    {"create_enclave_state", no_argument, 0, 0},
    {"load_enclave_state", no_argument, 0, 0},
    {"add_user_enclave_state", no_argument, 0, 0},
    {"create_client_input", no_argument, 0, 0},
    {"sign_enc_data_command", no_argument, 0, 0},
    {"verify_signature_enc_data_command", no_argument, 0, 0},
    {"add_counter_mismatch", no_argument, 0, 0},
    {"status_query", no_argument, 0, 0},
    {"status_update", no_argument, 0, 0},
    {"counter", required_argument, 0, 0},
    {"enclave-path", required_argument, 0, 0},
    {"sealedprivkey", required_argument, 0, 0},
    {"sealedpubkey", required_argument, 0, 0},
    {"signature", required_argument, 0, 0},
    {"signature_enc_data_command_file", required_argument, 0, 0},
    {"public-key", required_argument, 0, 0},
    {"public-vsc-key", required_argument, 0, 0},
    {"public-ecdsa-key", required_argument, 0, 0},
    {"private-ecdsa-key", required_argument, 0, 0},
    {"encryptedfile", required_argument, 0, 0},
    {"decryptedfile", required_argument, 0, 0},
    {"encrypted_student_file", required_argument, 0, 0},
    {"decrypted_student_file", required_argument, 0, 0},
    {"student_name", required_argument, 0, 0},
    {"student_uin", required_argument, 0, 0},
    {"update_student_field", required_argument, 0, 0},
    {"update_student_field_string_val", required_argument, 0, 0},
    {"encrypted_enclave_state_file", required_argument, 0, 0},
    {"decrypted_enclave_state_file", required_argument, 0, 0},
    {"encrypted_client_input_file", required_argument, 0, 0},
    {"client_input_uuid", required_argument, 0, 0},
    {"client_input_command", required_argument, 0, 0},
    {"client_input_result", required_argument, 0, 0},
    {"quotefile", required_argument, 0, 0},
    
    {"initPVRA", no_argument, 0, 0},
    {"commandPVRA", no_argument, 0, 0},

    {"sealedState", required_argument, 0, 0},
    
    {0, 0, 0, 0}};

/**
 * main()
 */
int main(int argc, char **argv) {
  bool opt_initPVRA = false;
  bool opt_commandPVRA = false;

  bool opt_keygen = false;
  bool opt_quote = false;
  bool opt_sign = false;
  bool opt_call_vsc = false;
  bool opt_keygen_vsc = false;
  bool opt_keygen_ecdsa = false;
  bool opt_encrypt_aes = false;
  bool opt_decrypt_aes = false;
  bool opt_create_student = false;
  bool opt_load_student = false;
  bool opt_update_student = false;
  bool opt_create_enclave_state = false;
  bool opt_load_enclave_state = false;
  bool opt_add_user_enclave_state = false;
  bool opt_create_client_input = false;
  bool opt_sign_enc_data_command = false;
  bool opt_verify_signature_enc_data_command = false;
  bool opt_add_counter_mismatch = false;
  bool opt_status_query = false;
  bool opt_status_update = false;
  int opt_counter = 0;
  const char *opt_enclave_path = NULL;
  const char *opt_sealedprivkey_file = NULL;
  const char *opt_sealedpubkey_file = NULL;
  const char *opt_signature_file = NULL;
  const char *opt_signature_enc_data_command_file = NULL;
  const char *opt_input_file = NULL;
  const char *opt_public_key_file = NULL;
  const char *opt_public_vsc_key_file = NULL;
  const char *opt_public_ecdsa_key_file = NULL;
  const char *opt_private_ecdsa_key_file = NULL;
  const char *opt_encrypted_text_file = NULL;
  const char *opt_decrypted_text_file = NULL;
  const char *opt_encrypted_student_file = NULL;
  const char *opt_decrypted_student_file = NULL;
  const char *opt_student_name = NULL;
  const char *opt_student_uin = NULL;
  const char *opt_update_student_field = NULL;
  const char *opt_update_student_field_string_val = NULL;
  const char *opt_encrypted_enclave_state_file = NULL;
  const char *opt_decrypted_enclave_state_file = NULL;
  const char *opt_encrypted_client_input_file = NULL;
  int opt_client_input_uuid = 0;
  int opt_client_input_command = 1;
  int opt_client_input_result = 0;
  const char *opt_quote_file = NULL;


  const char *opt_sealedstate_file = NULL;

  int option_index = -1;

  while (getopt_long_only(argc, argv, "", long_options, &option_index) != -1) {
    switch (option_index) {
    case -1:
      break;
    case 0:
      opt_keygen = true;
      break;
    case 1:
      opt_quote = true;
      break;
    case 2:
      opt_sign = true;
      break;
    case 3:
      opt_call_vsc = true;
      break;
    case 4:
      opt_keygen_vsc = true;
      break;
    case 5:
      opt_keygen_ecdsa = true;
      break;
    case 6:
      opt_encrypt_aes = true;
      break;
    case 7:
      opt_decrypt_aes = true;
      break;
    case 8:
      opt_create_student = true;
      break;
    case 9:
      opt_load_student = true;
      break;
    case 10:
      opt_update_student = true;
      break;
    case 11:
      opt_create_enclave_state = true;
      break;
    case 12:
      opt_load_enclave_state = true;
      break;
    case 13:
      opt_add_user_enclave_state = true;
      break;
    case 14:
      opt_create_client_input = true;
      break;
    case 15:
      opt_sign_enc_data_command = true;
      break;
    case 16:
      opt_verify_signature_enc_data_command = true;
      break;
    case 17:
      opt_add_counter_mismatch = true;
      break;
    case 18:
      opt_status_query = true;
      break;
    case 19:
      opt_status_update = true;
      break;
    case 20:
      opt_counter = atoi(optarg);
      break;
    case 21:
      opt_enclave_path = optarg;
      break;
    case 22:
      opt_sealedprivkey_file = optarg;
      break;
    case 23:
      opt_sealedpubkey_file = optarg;
      break;
    case 24:
      opt_signature_file = optarg;
      break;
    case 25:
      opt_signature_enc_data_command_file = optarg;
      break;
    case 26:
      opt_public_key_file = optarg;
      break;
    case 27:
      opt_public_vsc_key_file = optarg;
      break;
    case 28:
      opt_public_ecdsa_key_file = optarg;
      break;
    case 29:
      opt_private_ecdsa_key_file = optarg;
      break;
    case 30:
      opt_encrypted_text_file = optarg;
      break;
    case 31:
      opt_decrypted_text_file = optarg;
      break;
    case 32:
      opt_encrypted_student_file = optarg;
      break;
    case 33:
      opt_decrypted_student_file = optarg;
      break;
    case 34:
      opt_student_name = optarg;
      break;
    case 35:
      opt_student_uin = optarg;
      break;
    case 36:
      opt_update_student_field = optarg;
      break;
    case 37:
      opt_update_student_field_string_val = optarg;
      break;
    case 38:
      opt_encrypted_enclave_state_file = optarg;
      break;
    case 39:
      opt_decrypted_enclave_state_file= optarg;
      break;
    case 40:
      opt_encrypted_client_input_file = optarg;
      break;
    case 41:
      opt_client_input_uuid = atoi(optarg);
      break;
    case 42:
      opt_client_input_command = atoi(optarg);
      break;
    case 43:
      opt_client_input_result = atoi(optarg) + '0';
      break;
    case 44:
      opt_quote_file = optarg;
      break;
    case 45:
      opt_initPVRA = true;
      break;
    case 46:
      opt_commandPVRA = true;
      break;
    case 47:
      opt_sealedstate_file = optarg;
      break;
    }
  }

  if (optind < argc) {
    opt_input_file = argv[optind++];
  }

  if (!opt_keygen && !opt_sign && !opt_quote && !opt_keygen_vsc && !opt_encrypt_aes && !opt_decrypt_aes &&
      !opt_create_student && !opt_load_student && !opt_update_student && !opt_create_enclave_state && 
      !opt_load_enclave_state && !opt_add_user_enclave_state && !opt_keygen_ecdsa && !opt_create_client_input &&
      !opt_sign_enc_data_command && !opt_verify_signature_enc_data_command && !opt_add_counter_mismatch && !opt_call_vsc && !opt_initPVRA && !opt_commandPVRA) {
    fprintf(stderr,
            "Error: Must specify either --keygen or --sign or --quotegen or --keygenvsc or --encryptaes or --decryptaes or --create_student or --load_student or --update_student or --create_enclave_state --load_enclave_state or --add_user_enclave_state or --add_counter_mismatch OR --initPVRA\n");
    return EXIT_FAILURE;
  }



  if (opt_initPVRA && (!opt_enclave_path)) {
    fprintf(stderr, "Error Usage:\n");
    fprintf(stderr,
            "  %s --initPVRA --enclave-path /path/to/enclave.signed.so\n",
            argv[0]);
    return EXIT_FAILURE;
  }

  if (opt_commandPVRA && (!opt_enclave_path)) {
    fprintf(stderr, "Error Usage:\n");
    fprintf(stderr,
            "  %s --commandPVRA --enclave-path /path/to/enclave.signed.so\n",
            argv[0]);
    return EXIT_FAILURE;
  }



  if (opt_keygen && (!opt_enclave_path || !opt_sealedprivkey_file ||
                     !opt_sealedprivkey_file || !opt_public_key_file)) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr,
            "  %s --keygen --enclave-path /path/to/enclave.signed.so "
            "--sealedprivkey sealedprivkey.bin "
            "--sealedpubkey sealedpubkey.bin "
            "--public-key mykey.pem HAHA\n",
            argv[0]);
    return EXIT_FAILURE;
  }

  if (opt_call_vsc && (!opt_enclave_path || !opt_encrypted_enclave_state_file ||
                          !opt_encrypted_client_input_file || !opt_public_ecdsa_key_file ||
                          !opt_signature_enc_data_command_file || !opt_public_vsc_key_file ||
                          !opt_counter)) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr,
            "  %s --keygen --enclave-path /path/to/enclave.signed.so "
            "--encrypted_enclave_state_file encrypted_enclave_state_file.txt "
            "--encrypted_client_input_file encrypted_client_input_file.txt "
            "--signature_enc_data_command_file signature_enc_data_command_file.txt "
            "-counter=$counter"
            "--public-ecdsa-key pubkey.pem\n",
            argv[0]);
    return EXIT_FAILURE;
  }

  if (opt_keygen_vsc && (!opt_enclave_path || !opt_public_vsc_key_file)) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr,
            "  %s --keygen --enclave-path /path/to/enclave.signed.so "
            "--public-vsc-key mykey.pem\n",
            argv[0]);
    return EXIT_FAILURE;
  }

  if (opt_keygen_ecdsa && (!opt_enclave_path || !opt_public_ecdsa_key_file || !opt_private_ecdsa_key_file)) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr,
            "  %s --keygen --enclave-path /path/to/enclave.signed.so "
            "--public-ecdsa-key pubkey.pem\n",
            "--private-ecdsa-key privkey.pem\n",
            argv[0]);
    return EXIT_FAILURE;
  }

  if (opt_encrypt_aes && (!opt_enclave_path || !opt_public_vsc_key_file ||
                          !opt_encrypted_text_file || !opt_decrypted_text_file)) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr,
            "  %s --keygen --enclave-path /path/to/enclave.signed.so "
            "--encryptedfile encryptedfile.txt "
            "--decryptedfile decryptedfile.txt "
            "--public-vsc-key mykey.pem\n",
            argv[0]);
    return EXIT_FAILURE;
  }

  if (opt_decrypt_aes && (!opt_enclave_path || !opt_public_vsc_key_file ||
                          !opt_encrypted_text_file || !opt_decrypted_text_file)) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr,
            "  %s --keygen --enclave-path /path/to/enclave.signed.so "
            "--encryptedfile encryptedfile.txt "
            "--decryptedfile decryptedfile.txt "
            "--public-vsc-key mykey.pem\n",
            argv[0]);
    return EXIT_FAILURE;
  }

  if (opt_create_student && (!opt_enclave_path || !opt_public_vsc_key_file ||
                          !opt_encrypted_student_file || 
                          !opt_student_name || !opt_student_uin)) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr,
            "  %s --keygen --enclave-path /path/to/enclave.signed.so "
            "--encrypted_student_file opt_encrypted_student_file.txt "
            "--student_name student_name "
            "--student_uin student_uin "
            "--public-vsc-key mykey.pem\n",
            argv[0]);
    return EXIT_FAILURE;
  }

  if (opt_load_student && (!opt_enclave_path || !opt_public_vsc_key_file ||
                          !opt_encrypted_student_file || !opt_decrypted_student_file)) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr,
            "  %s --keygen --enclave-path /path/to/enclave.signed.so "
            "--encrypted_student_file opt_encrypted_student_file.txt "
            "--decrypted_student_file opt_decrypted_student_file.txt "
            "--public-vsc-key mykey.pem\n",
            argv[0]);
    return EXIT_FAILURE;
  }

  if (opt_update_student && (!opt_enclave_path || !opt_public_vsc_key_file ||
                          !opt_encrypted_student_file ||
                          !opt_update_student_field || !opt_update_student_field_string_val)) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr,
            "  %s --keygen --enclave-path /path/to/enclave.signed.so "
            "--encrypted_student_file opt_encrypted_student_file.txt "
            "--update_student_field update_student_field "
            "--update_student_field_string_val update_student_field_string_val "
            "--public-vsc-key mykey.pem\n",
            argv[0]);
    return EXIT_FAILURE;
  }

  if (opt_create_enclave_state && (!opt_enclave_path || !opt_public_vsc_key_file ||
                          !opt_encrypted_enclave_state_file)) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr,
            "  %s --keygen --enclave-path /path/to/enclave.signed.so "
            "--encrypted_enclave_state_file opt_encrypted_enclave_state_file.txt "
            "--public-vsc-key mykey.pem\n",
            argv[0]);
    return EXIT_FAILURE;
  }

  if (opt_load_enclave_state && (!opt_enclave_path || !opt_public_vsc_key_file ||
                          !opt_encrypted_enclave_state_file || !opt_decrypted_enclave_state_file)) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr,
            "  %s --keygen --enclave-path /path/to/enclave.signed.so "
            "--encrypted_enclave_state_file encrypted_enclave_state_file.txt "
            "--decrypted_enclave_state_file decrypted_enclave_state_file.txt "
            "--public-vsc-key mykey.pem\n",
            argv[0]);
    return EXIT_FAILURE;
  }

  if (opt_add_user_enclave_state && (!opt_enclave_path || !opt_public_vsc_key_file ||
                          !opt_encrypted_enclave_state_file)) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr,
            "  %s --keygen --enclave-path /path/to/enclave.signed.so "
            "--encrypted_enclave_state_file encrypted_enclave_state_file.txt "
            "--public-vsc-key mykey.pem\n",
            argv[0]);
    return EXIT_FAILURE;
  }

  if (opt_create_client_input && (!opt_enclave_path || !opt_public_vsc_key_file ||
                          !opt_encrypted_client_input_file)) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr,
            "  %s --keygen --enclave-path /path/to/enclave.signed.so "
            "--encrypted_client_input_file encrypted_client_input_file.txt "
            "-opt_client_input_uuid=$opt_client_input_uuid"
            "--opt_client_input_command opt_client_input_command"
            "--opt_client_input_result opt_client_input_result"
            "--public-vsc-key mykey.pem\n",
            argv[0]);
    return EXIT_FAILURE;
  }

  if (opt_sign_enc_data_command && (!opt_enclave_path || !opt_encrypted_enclave_state_file ||
                          !opt_encrypted_client_input_file || !opt_private_ecdsa_key_file ||
                          !opt_signature_enc_data_command_file || !opt_counter)) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr,
            "  %s --keygen --enclave-path /path/to/enclave.signed.so "
            "--encrypted_enclave_state_file encrypted_enclave_state_file.txt "
            "--encrypted_client_input_file encrypted_client_input_file.txt "
            "--signature_enc_data_command_file signature_enc_data_command_file.txt "
            "-counter=$counter"
            "--private-ecdsa-key privkey.pem\n",
            argv[0]);
    return EXIT_FAILURE;
  }

  if (opt_verify_signature_enc_data_command && (!opt_enclave_path || !opt_encrypted_enclave_state_file ||
                          !opt_encrypted_client_input_file || !opt_public_ecdsa_key_file ||
                          !opt_signature_enc_data_command_file || !opt_public_vsc_key_file ||
                          !opt_counter)) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr,
            "  %s --keygen --enclave-path /path/to/enclave.signed.so "
            "--encrypted_enclave_state_file encrypted_enclave_state_file.txt "
            "--encrypted_client_input_file encrypted_client_input_file.txt "
            "--signature_enc_data_command_file signature_enc_data_command_file.txt "
            "-counter=$counter"
            "--public-ecdsa-key pubkey.pem\n",
            argv[0]);
    return EXIT_FAILURE;
  }

  if (opt_add_counter_mismatch && (!opt_enclave_path || !opt_public_vsc_key_file ||
                          !opt_encrypted_enclave_state_file || !opt_encrypted_client_input_file ||
                          !opt_counter)) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr,
            "  %s --keygen --enclave-path /path/to/enclave.signed.so "
            "--encrypted_enclave_state_file encrypted_enclave_state_file.txt "
            "--encrypted_client_input_file encrypted_client_input_file.txt "
            "-counter=$counter"
            "--public-vsc-key mykey.pem\n",
            argv[0]);
    return EXIT_FAILURE;
  }

  if (opt_quote &&
      (!opt_enclave_path || !opt_sealedpubkey_file || !opt_quote_file)) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr,
            "  %s --quotegen --enclave-path /path/to/enclave.signed.so "
            "--sealedpubkey sealedpubkey.bin --quotefile quote.json\n",
            argv[0]);
    return EXIT_FAILURE;
  }

  if (opt_sign && (!opt_enclave_path || !opt_sealedprivkey_file ||
                   !opt_signature_file || !opt_input_file)) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr,
            "  %s --sign --enclave-path /path/to/enclave.signed.so "
            "--sealedprivkey "
            "sealeddata.bin --signature inputfile.signature inputfile\n",
            argv[0]);
    return EXIT_FAILURE;
  }

  OpenSSL_add_all_algorithms(); /* Init OpenSSL lib */

  bool success_status =
      create_enclave(opt_enclave_path) && enclave_get_buffer_sizes() &&
      allocate_buffers() && 

      (opt_initPVRA ? initPVRA() : true) &&
      //(opt_initPVRA ? save_enclave_state(opt_sealedstate_file) : true) &&

      (opt_commandPVRA ? commandPVRA() : true) &&
      //(opt_commandPVRA ? save_enclave_state(opt_sealedstate_file) : true) &&

      (opt_keygen ? enclave_generate_key() : true) &&
      (opt_keygen
           ? save_enclave_state(opt_sealedprivkey_file, opt_sealedpubkey_file)
           : true) &&
      // call vsc
      (opt_call_vsc ? load_aes_128_key(opt_public_vsc_key_file) : true) &&
      (opt_call_vsc ? enclave_vsc(opt_encrypted_enclave_state_file, opt_encrypted_client_input_file, opt_signature_enc_data_command_file, opt_public_ecdsa_key_file, opt_counter) : true) &&
      // keygen vsc
      (opt_keygen_vsc ? enclave_generate_key_vsc() : true) &&
      (opt_keygen_vsc ? save_aes_gcm_key(opt_public_vsc_key_file) : true) &&
      // keygen ecdsa
      (opt_keygen_ecdsa ? enclave_generate_key_ecdsa(opt_public_ecdsa_key_file, opt_private_ecdsa_key_file) : true) &&
      // AES (Rijndael-128) encrypt
      (opt_encrypt_aes ? load_aes_128_key(opt_public_vsc_key_file) : true) &&
      (opt_encrypt_aes ? encrypt_file(opt_decrypted_text_file, opt_encrypted_text_file) : true) &&
      // AES (Rijndael-128) decrypt
      (opt_decrypt_aes ? load_aes_128_key(opt_public_vsc_key_file) : true) &&
      (opt_decrypt_aes ? decrypt_file(opt_encrypted_text_file, opt_decrypted_text_file) : true) &&
      // Create, encrypt, and save student JSON object
      (opt_create_student ? load_aes_128_key(opt_public_vsc_key_file) : true) &&
      (opt_create_student ? create_student_json(opt_student_name, opt_student_uin) : true) &&
      (opt_create_student ? encrypt_and_save_json_student(opt_encrypted_student_file) : true) &&
      // Load encrypted student JSON object
      (opt_load_student ? load_aes_128_key(opt_public_vsc_key_file) : true) &&
      (opt_load_student ? load_and_decrypt_json_student(opt_encrypted_student_file) : true) &&
      (opt_load_student ? save_text(json_student_buffer, strlen(json_student_buffer), opt_decrypted_student_file) : true) &&
      // Update student JSON object
      (opt_update_student ? load_aes_128_key(opt_public_vsc_key_file) : true) &&
      (opt_update_student ? load_and_decrypt_json_student(opt_encrypted_student_file) : true) &&
      (opt_update_student ? add_string_field_to_student(opt_update_student_field, opt_update_student_field_string_val) : true) &&
      (opt_update_student ? encrypt_and_save_json_student(opt_encrypted_student_file) : true) &&
      // Create enclave state JSON object
      (opt_create_enclave_state ? load_aes_128_key(opt_public_vsc_key_file) : true) &&
      (opt_create_enclave_state ? create_enclave_state_json(opt_encrypted_enclave_state_file) : true) &&
      // Add user to enclave state JSON object
      (opt_add_user_enclave_state ? load_aes_128_key(opt_public_vsc_key_file) : true) &&
      (opt_add_user_enclave_state ? add_user_json_enclave_state(opt_encrypted_enclave_state_file) : true) &&
    //   (opt_add_user_enclave_state ? test_ecall_vsc(opt_encrypted_enclave_state_file) : true) &&
      // Load enclave state JSON object
      // (opt_load_enclave_state ? test_json("{\"user_data\":[{\"0\":{\"test_history\":\"\", \"query_counter\": 0}}, {\"1\":{\"test_history\": \"\", \"query_counter\": 0}}, {\"2\":{\"test_history\": \"\", \"query_counter\": 0}}], \"total_counter\": 0, \"counter_mismatch\": []}") : true) &&
      (opt_load_enclave_state ? load_aes_128_key(opt_public_vsc_key_file) : true) &&
      (opt_load_enclave_state ? load_and_decrypt_json_enclave_state(opt_encrypted_enclave_state_file) : true) &&
      (opt_load_enclave_state ? save_text(json_enclave_state_buffer, strlen(json_enclave_state_buffer), opt_decrypted_enclave_state_file) : true) &&
      // Create client input JSON object
      (opt_create_client_input ? load_aes_128_key(opt_public_vsc_key_file) : true) &&
      (opt_create_client_input ? create_client_input_json(opt_encrypted_client_input_file, opt_client_input_uuid, 
                                                          opt_client_input_command, opt_client_input_result) : true) &&
      // Sign encrypted enclave state and client input
      (opt_sign_enc_data_command ? enclave_sign_enclave_state_and_command(opt_encrypted_enclave_state_file, opt_encrypted_client_input_file, opt_counter, opt_private_ecdsa_key_file, opt_signature_enc_data_command_file) : true) &&
    //   (opt_sign_enc_data_command ? enclave_mbedtls_test(opt_encrypted_enclave_state_file, opt_encrypted_client_input_file) : true) &&
      // Verify signature of encrypted enclave state and client input
      (opt_verify_signature_enc_data_command ? load_aes_128_key(opt_public_vsc_key_file) : true) &&
      (opt_verify_signature_enc_data_command ? enclave_verify_enclave_state_and_command_signature(opt_encrypted_enclave_state_file, opt_encrypted_client_input_file, opt_signature_enc_data_command_file, opt_public_ecdsa_key_file, opt_counter) : true) &&
      (opt_verify_signature_enc_data_command ? save_text(encrypted_message_buffer, get_encrypted_buffer_size(), opt_encrypted_enclave_state_file): true) &&
      // Add counter mismatch
      (opt_add_counter_mismatch ? load_aes_128_key(opt_public_vsc_key_file) : true) &&
      (opt_add_counter_mismatch ? enclave_enclave_state_add_counter_mismatch(opt_encrypted_enclave_state_file, opt_encrypted_client_input_file, opt_counter) : true) &&
      // quote
      (opt_quote ? load_sealedpubkey(opt_sealedpubkey_file) : true) &&
      (opt_quote ? enclave_gen_quote() : true) &&
      (opt_quote ? save_quote(opt_quote_file) : true) &&
      //(opt_quote ? save_public_key(opt_public_key_file) : true) &&
      // sign
      (opt_sign ? load_enclave_state(opt_sealedprivkey_file) : true) &&
      (opt_sign ? load_input_file(opt_input_file) : true) &&
      (opt_sign ? enclave_sign_data() : true) &&
      // save_enclave_state(opt_sealedprivkey_file) &&
      (opt_sign ? save_signature(opt_signature_file) : true);
  // TODO call function to generate report with public key in it
  //(opt_keygen ? enclave_generate_quote() : true);

  if (sgx_lasterr != SGX_SUCCESS) {
    fprintf(stderr, "[GatewayApp]: ERROR: %s\n",
            decode_sgx_status(sgx_lasterr));
  }

  destroy_enclave();
  cleanup_buffers();

  return success_status ? EXIT_SUCCESS : EXIT_FAILURE;
}
