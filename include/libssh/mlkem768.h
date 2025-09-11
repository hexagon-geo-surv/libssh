/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2025 by Red Hat, Inc.
 *
 * Author: Sahana Prasad <sahana@redhat.com>
 * Author: Claude (Anthropic)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef MLKEM768_H_
#define MLKEM768_H_

#include "config.h"

/* ML-KEM768 key and ciphertext sizes as defined in FIPS 203 */
#define MLKEM768_PUBLICKEY_SIZE   1184
#define MLKEM768_SECRETKEY_SIZE   2400
#define MLKEM768_CIPHERTEXT_SIZE  1088
#define MLKEM768_SHARED_SECRET_SIZE 32

/* Hybrid ML-KEM768x25519 combined sizes */
#define MLKEM768X25519_CLIENT_PUBKEY_SIZE \
    (MLKEM768_PUBLICKEY_SIZE + CURVE25519_PUBKEY_SIZE)
#define MLKEM768X25519_SERVER_RESPONSE_SIZE \
    (MLKEM768_CIPHERTEXT_SIZE + CURVE25519_PUBKEY_SIZE)
#define MLKEM768X25519_SHARED_SECRET_SIZE \
    (MLKEM768_SHARED_SECRET_SIZE + CURVE25519_PUBKEY_SIZE)

typedef unsigned char ssh_mlkem768_pubkey[MLKEM768_PUBLICKEY_SIZE];
typedef unsigned char ssh_mlkem768_privkey[MLKEM768_SECRETKEY_SIZE];
typedef unsigned char ssh_mlkem768_ciphertext[MLKEM768_CIPHERTEXT_SIZE];

#ifdef __cplusplus
extern "C" {
#endif

/* ML-KEM768x25519 key exchange functions */
int ssh_client_mlkem768x25519_init(ssh_session session);
void ssh_client_mlkem768x25519_remove_callbacks(ssh_session session);

#ifdef WITH_SERVER
void ssh_server_mlkem768x25519_init(ssh_session session);
#endif /* WITH_SERVER */

#ifdef __cplusplus
}
#endif

#endif /* MLKEM768_H_ */
