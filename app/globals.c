/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "app.h"


/* Globals */

uint64_t tsc_dump[50];
int tsc_idx;

sgx_enclave_id_t enclave_id;
sgx_launch_token_t launch_token;
int launch_token_updated;
sgx_status_t sgx_lasterr;


void *quote_buffer;
size_t quote_buffer_size;

void *signature_buffer;
size_t signature_buffer_size;
size_t signature_rec_buffer_size;

void *sealed_state_buffer;
size_t sealed_state_buffer_size;


void *pub_enckey_buffer;
size_t pub_enckey_buffer_size;


void *signedFT_buffer;
size_t signedFT_buffer_size;
void *eCMD_buffer;
size_t eCMD_buffer_size;
void *eAESkey_buffer;
size_t eAESkey_buffer_size;



void *cResponse_buffer;
size_t cResponse_buffer_size;

void *cRsig_buffer;
size_t cRsig_buffer_size;

void *sealed_out_buffer;
size_t sealed_out_buffer_size;


void *FT_buffer;
size_t FT_buffer_size;


void *pubkeys_buffer;
size_t pubkeys_buffer_size;

void *sigpubkeys_buffer;
size_t sigpubkeys_buffer_size;

void *auditlog_buffer;
size_t auditlog_buffer_size;

void *auditlog_signature_buffer;
size_t auditlog_signature_buffer_size;


int actual_auditlog_size;

