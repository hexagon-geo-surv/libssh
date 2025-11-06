/*
 * mlkem768x25519.c - ML-KEM768x25519 hybrid key exchange
 * mlkem768x25519-sha256
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2025 by Red Hat, Inc.
 *
 * Author: Sahana Prasad <sahana@redhat.com>
 * Author: Claude (Anthropic)
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, version 2.1 of the License.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#include "libssh/bignum.h"
#include "libssh/buffer.h"
#include "libssh/crypto.h"
#include "libssh/curve25519.h"
#include "libssh/dh.h"
#include "libssh/mlkem768.h"
#include "libssh/pki.h"
#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/ssh2.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

static SSH_PACKET_CALLBACK(ssh_packet_client_mlkem768x25519_reply);

static ssh_packet_callback dh_client_callbacks[] = {
    ssh_packet_client_mlkem768x25519_reply,
};

static struct ssh_packet_callbacks_struct ssh_mlkem768x25519_client_callbacks =
    {
        .start = SSH2_MSG_KEX_HYBRID_REPLY,
        .n_callbacks = 1,
        .callbacks = dh_client_callbacks,
        .user = NULL,
};

/* Generate ML-KEM768 keypair using OpenSSL */
static int mlkem768_keypair_gen(ssh_mlkem768_pubkey pubkey,
                                ssh_mlkem768_privkey privkey)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int rc, ret = SSH_ERROR;
    size_t pubkey_len = MLKEM768_PUBLICKEY_SIZE;
    size_t privkey_len = MLKEM768_SECRETKEY_SIZE;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    if (ctx == NULL) {
        SSH_LOG(SSH_LOG_WARNING,
                "Failed to create ML-KEM-768 context: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    rc = EVP_PKEY_keygen_init(ctx);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_WARNING,
                "Failed to initialize ML-KEM-768 keygen: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    rc = EVP_PKEY_keygen(ctx, &pkey);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_WARNING,
                "Failed to perform ML-KEM-768 keygen: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    rc = EVP_PKEY_get_raw_public_key(pkey, pubkey, &pubkey_len);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_WARNING,
                "Failed to extract ML-KEM-768 public key: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    rc = EVP_PKEY_get_raw_private_key(pkey, privkey, &privkey_len);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_WARNING,
                "Failed to extract ML-KEM-768 private key: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    ret = SSH_OK;

cleanup:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/* Encapsulate shared secret using ML-KEM768 - used by server side */
static int mlkem768_encapsulate(const ssh_mlkem768_pubkey pubkey,
                                ssh_mlkem768_ciphertext ciphertext,
                                unsigned char *shared_secret)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int rc, ret = SSH_ERROR;
    size_t ct_len = MLKEM768_CIPHERTEXT_SIZE;
    size_t ss_len = MLKEM768_SHARED_SECRET_SIZE;

    pkey = EVP_PKEY_new_raw_public_key_ex(NULL,
                                          "ML-KEM-768",
                                          NULL,
                                          pubkey,
                                          MLKEM768_PUBLICKEY_SIZE);
    if (pkey == NULL) {
        SSH_LOG(SSH_LOG_WARNING,
                "Failed to create ML-KEM-768 public key from raw data: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (ctx == NULL) {
        SSH_LOG(SSH_LOG_WARNING,
                "Failed to create ML-KEM-768 context: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    rc = EVP_PKEY_encapsulate_init(ctx, NULL);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_WARNING,
                "Failed to initialize ML-KEM-768 encapsulation: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    rc = EVP_PKEY_encapsulate(ctx, ciphertext, &ct_len, shared_secret, &ss_len);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_WARNING,
                "Failed to perform ML-KEM-768 encapsulation: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    ret = SSH_OK;

cleanup:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/* Decapsulate shared secret using ML-KEM768 - used by client side */
static int mlkem768_decapsulate(const ssh_mlkem768_privkey privkey,
                                const ssh_mlkem768_ciphertext ciphertext,
                                unsigned char *shared_secret)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int rc, ret = SSH_ERROR;
    size_t ss_len = MLKEM768_SHARED_SECRET_SIZE;

    pkey = EVP_PKEY_new_raw_private_key_ex(NULL,
                                           "ML-KEM-768",
                                           NULL,
                                           privkey,
                                           MLKEM768_SECRETKEY_SIZE);
    if (pkey == NULL) {
        SSH_LOG(SSH_LOG_WARNING,
                "Failed to create ML-KEM-768 context: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (ctx == NULL) {
        SSH_LOG(SSH_LOG_WARNING,
                "Failed to create ML-KEM-768 context: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    rc = EVP_PKEY_decapsulate_init(ctx, NULL);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_WARNING,
                "Failed to initialize ML-KEM-768 decapsulation: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    rc = EVP_PKEY_decapsulate(ctx,
                              shared_secret,
                              &ss_len,
                              ciphertext,
                              MLKEM768_CIPHERTEXT_SIZE);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_WARNING,
                "Failed to perform ML-KEM-768 decapsulation: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    ret = SSH_OK;

cleanup:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

int ssh_client_mlkem768x25519_init(ssh_session session)
{
    struct ssh_crypto_struct *crypto = session->next_crypto;
    ssh_buffer client_pubkey = NULL;
    ssh_string pubkey_blob = NULL;
    int rc;

    SSH_LOG(SSH_LOG_TRACE, "Initializing ML-KEM768x25519 key exchange");

    /* Initialize Curve25519 component first */
    rc = ssh_curve25519_init(session);
    if (rc != SSH_OK) {
        return rc;
    }

    /* Generate ML-KEM768 keypair */
    rc = mlkem768_keypair_gen(crypto->mlkem768_client_pubkey,
                              crypto->mlkem768_client_privkey);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Failed to generate ML-KEM768 keypair");
        return SSH_ERROR;
    }

    /* Create hybrid client public key: ML-KEM768 + Curve25519 */
    client_pubkey = ssh_buffer_new();
    if (client_pubkey == NULL) {
        session->session_state = SSH_SESSION_STATE_ERROR;
        rc = SSH_ERROR;
        goto cleanup;
    }

    rc = ssh_buffer_pack(client_pubkey,
                         "PP",
                         MLKEM768_PUBLICKEY_SIZE,
                         crypto->mlkem768_client_pubkey,
                         CURVE25519_PUBKEY_SIZE,
                         crypto->curve25519_client_pubkey);
    if (rc != SSH_OK) {
        session->session_state = SSH_SESSION_STATE_ERROR;
        rc = SSH_ERROR;
        goto cleanup;
    }

    /* Convert to string for sending */
    pubkey_blob = ssh_string_new(ssh_buffer_get_len(client_pubkey));
    if (pubkey_blob == NULL) {
        session->session_state = SSH_SESSION_STATE_ERROR;
        rc = SSH_ERROR;
        goto cleanup;
    }
    ssh_string_fill(pubkey_blob,
                    ssh_buffer_get(client_pubkey),
                    ssh_buffer_get_len(client_pubkey));

    /* Send the hybrid public key to server */
    rc = ssh_buffer_pack(session->out_buffer,
                         "bS",
                         SSH2_MSG_KEX_HYBRID_INIT,
                         pubkey_blob);
    if (rc != SSH_OK) {
        session->session_state = SSH_SESSION_STATE_ERROR;
        rc = SSH_ERROR;
        goto cleanup;
    }

    session->dh_handshake_state = DH_STATE_INIT_SENT;

    ssh_packet_set_callbacks(session, &ssh_mlkem768x25519_client_callbacks);
    rc = ssh_packet_send(session);
    if (rc == SSH_ERROR) {
        ssh_set_error(session, SSH_FATAL, "Failed to send SSH_MSG_KEX_ECDH_INIT");
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

cleanup:
    ssh_buffer_free(client_pubkey);
    ssh_string_free(pubkey_blob);
    return rc;
}

static SSH_PACKET_CALLBACK(ssh_packet_client_mlkem768x25519_reply)
{
    struct ssh_crypto_struct *crypto = session->next_crypto;
    ssh_string s_server_blob = NULL;
    ssh_string s_pubkey_blob = NULL;
    ssh_string s_signature = NULL;
    const unsigned char *server_data = NULL;
    unsigned char mlkem_shared_secret[MLKEM768_SHARED_SECRET_SIZE];
    unsigned char curve25519_shared_secret[CURVE25519_PUBKEY_SIZE];
    unsigned char combined_secret[MLKEM768X25519_SHARED_SECRET_SIZE];
    unsigned char hashed_secret[SHA256_DIGEST_LEN];
    size_t server_blob_len;
    int rc;
    (void)type;
    (void)user;

    SSH_LOG(SSH_LOG_TRACE, "Received ML-KEM768x25519 server reply");

    ssh_client_mlkem768x25519_remove_callbacks(session);

    s_pubkey_blob = ssh_buffer_get_ssh_string(packet);
    if (s_pubkey_blob == NULL) {
        ssh_set_error(session, SSH_FATAL, "No public key in packet");
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    rc = ssh_dh_import_next_pubkey_blob(session, s_pubkey_blob);
    if (rc != 0) {
        ssh_set_error(session, SSH_FATAL, "Failed to import next public key");
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    /* Get server blob containing ML-KEM768 ciphertext + Curve25519 pubkey */
    s_server_blob = ssh_buffer_get_ssh_string(packet);
    if (s_server_blob == NULL) {
        ssh_set_error(session, SSH_FATAL, "No server blob in packet");
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    server_data = ssh_string_data(s_server_blob);
    server_blob_len = ssh_string_len(s_server_blob);

    /* Expect ML-KEM768 ciphertext + Curve25519 pubkey */
    if (server_blob_len != MLKEM768X25519_SERVER_RESPONSE_SIZE) {
        ssh_set_error(session, SSH_FATAL, "Invalid server blob size");
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    /* Store ML-KEM768 ciphertext for sessionid calculation */
    memcpy(crypto->mlkem768_ciphertext, server_data, MLKEM768_CIPHERTEXT_SIZE);

    /* Decapsulate ML-KEM768 shared secret */
    rc = mlkem768_decapsulate(crypto->mlkem768_client_privkey,
                              crypto->mlkem768_ciphertext,
                              mlkem_shared_secret);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "ML-KEM768 decapsulation failed");
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    /* Store server Curve25519 public key for shared secret computation */
    memcpy(crypto->curve25519_server_pubkey,
           server_data + MLKEM768_CIPHERTEXT_SIZE,
           CURVE25519_PUBKEY_SIZE);

    /* Derive Curve25519 shared secret using existing libssh function */
    rc = ssh_curve25519_create_k(session, curve25519_shared_secret);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Curve25519 ECDH failed");
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    /* Combine secrets: ML-KEM768 + Curve25519 for hybrid approach */
    memcpy(combined_secret, mlkem_shared_secret, MLKEM768_SHARED_SECRET_SIZE);
    memcpy(combined_secret + MLKEM768_SHARED_SECRET_SIZE,
           curve25519_shared_secret,
           CURVE25519_PUBKEY_SIZE);

    sha256(combined_secret, MLKEM768X25519_SHARED_SECRET_SIZE, hashed_secret);

    bignum_bin2bn(hashed_secret, SHA256_DIGEST_LEN, &crypto->shared_secret);
    if (crypto->shared_secret == NULL) {
        ssh_set_error(session, SSH_FATAL, "Failed to create shared secret bignum");
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    /* Get signature for verification */
    s_signature = ssh_buffer_get_ssh_string(packet);
    if (s_signature == NULL) {
        ssh_set_error(session, SSH_FATAL, "No signature in packet");
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    crypto->dh_server_signature = s_signature;
    s_signature = NULL;

    /* Send the MSG_NEWKEYS */
    rc = ssh_packet_send_newkeys(session);
    if (rc == SSH_ERROR) {
        ssh_set_error(session, SSH_FATAL, "Failed to send SSH_MSG_NEWKEYS");
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }
    session->dh_handshake_state = DH_STATE_NEWKEYS_SENT;

cleanup:
    /* Clear sensitive data */
    explicit_bzero(mlkem_shared_secret, sizeof(mlkem_shared_secret));
    explicit_bzero(curve25519_shared_secret, sizeof(curve25519_shared_secret));
    explicit_bzero(combined_secret, sizeof(combined_secret));
    explicit_bzero(hashed_secret, sizeof(hashed_secret));
    ssh_string_free(s_pubkey_blob);
    ssh_string_free(s_server_blob);
    ssh_string_free(s_signature);
    return SSH_PACKET_USED;
}

void ssh_client_mlkem768x25519_remove_callbacks(ssh_session session)
{
    ssh_packet_remove_callbacks(session, &ssh_mlkem768x25519_client_callbacks);
}

#ifdef WITH_SERVER

static SSH_PACKET_CALLBACK(ssh_packet_server_mlkem768x25519_init);

static ssh_packet_callback dh_server_callbacks[] = {
    ssh_packet_server_mlkem768x25519_init,
};

static struct ssh_packet_callbacks_struct ssh_mlkem768x25519_server_callbacks =
    {
        .start = SSH2_MSG_KEX_HYBRID_INIT,
        .n_callbacks = 1,
        .callbacks = dh_server_callbacks,
        .user = NULL,
};

static SSH_PACKET_CALLBACK(ssh_packet_server_mlkem768x25519_init)
{
    struct ssh_crypto_struct *crypto = session->next_crypto;
    ssh_string client_pubkey_blob = NULL;
    ssh_string server_pubkey_blob = NULL;
    ssh_buffer server_response = NULL;
    const unsigned char *client_data = NULL;
    unsigned char mlkem_shared_secret[MLKEM768_SHARED_SECRET_SIZE];
    unsigned char curve25519_shared_secret[CURVE25519_PUBKEY_SIZE];
    unsigned char combined_secret[MLKEM768X25519_SHARED_SECRET_SIZE];
    unsigned char mlkem_ciphertext[MLKEM768_CIPHERTEXT_SIZE];
    unsigned char hashed_secret[SHA256_DIGEST_LEN];
    size_t client_blob_len;
    ssh_key privkey = NULL;
    enum ssh_digest_e digest = SSH_DIGEST_AUTO;
    ssh_string sig_blob = NULL;
    ssh_string server_hostkey_blob = NULL;
    int rc = SSH_ERROR;
    (void)type;
    (void)user;

    SSH_LOG(SSH_LOG_TRACE, "Received ML-KEM768x25519 client init");

    ssh_packet_remove_callbacks(session, &ssh_mlkem768x25519_server_callbacks);

    /* Get client hybrid public key: ML-KEM768 + Curve25519 */
    client_pubkey_blob = ssh_buffer_get_ssh_string(packet);
    if (client_pubkey_blob == NULL) {
        ssh_set_error(session, SSH_FATAL, "No client public key in packet");
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    client_data = ssh_string_data(client_pubkey_blob);
    client_blob_len = ssh_string_len(client_pubkey_blob);

    /* Expect ML-KEM768 pubkey + Curve25519 pubkey */
    if (client_blob_len != MLKEM768X25519_CLIENT_PUBKEY_SIZE) {
        ssh_set_error(session, SSH_FATAL, "Invalid client public key size");
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    /* Extract client ML-KEM768 public key */
    memcpy(crypto->mlkem768_client_pubkey,
           client_data,
           MLKEM768_PUBLICKEY_SIZE);

    /* Extract client Curve25519 public key */
    memcpy(crypto->curve25519_client_pubkey,
           client_data + MLKEM768_PUBLICKEY_SIZE,
           CURVE25519_PUBKEY_SIZE);

    /* Generate server Curve25519 keypair */
    rc = ssh_curve25519_init(session);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Failed to generate server Curve25519 key");
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    /* Derive Curve25519 shared secret */
    rc = ssh_curve25519_create_k(session, curve25519_shared_secret);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Curve25519 ECDH failed");
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    /* Encapsulate ML-KEM768 shared secret using client's public key */
    rc = mlkem768_encapsulate(client_data, mlkem_ciphertext, mlkem_shared_secret);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "ML-KEM768 encapsulation failed");
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    /* Store ML-KEM768 ciphertext for sessionid calculation */
    memcpy(crypto->mlkem768_ciphertext, mlkem_ciphertext, MLKEM768_CIPHERTEXT_SIZE);

    /* Combine secrets: ML-KEM768 + Curve25519 for hybrid approach */
    memcpy(combined_secret, mlkem_shared_secret, MLKEM768_SHARED_SECRET_SIZE);
    memcpy(combined_secret + MLKEM768_SHARED_SECRET_SIZE,
           curve25519_shared_secret,
           CURVE25519_PUBKEY_SIZE);

    sha256(combined_secret, MLKEM768X25519_SHARED_SECRET_SIZE, hashed_secret);

    /* Store the combined secret */
    bignum_bin2bn(hashed_secret, SHA256_DIGEST_LEN, &crypto->shared_secret);
    if (crypto->shared_secret == NULL) {
        ssh_set_error(session, SSH_FATAL, "Failed to create shared secret bignum");
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    /* Create server response: ML-KEM768 ciphertext + Curve25519 pubkey */
    server_response = ssh_buffer_new();
    if (server_response == NULL) {
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    rc = ssh_buffer_pack(server_response,
                         "PP",
                         MLKEM768_CIPHERTEXT_SIZE,
                         mlkem_ciphertext,
                         CURVE25519_PUBKEY_SIZE,
                         crypto->curve25519_server_pubkey);
    if (rc != SSH_OK) {
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    /* Convert to string for sending */
    server_pubkey_blob = ssh_string_new(ssh_buffer_get_len(server_response));
    if (server_pubkey_blob == NULL) {
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }
    ssh_string_fill(server_pubkey_blob,
                    ssh_buffer_get(server_response),
                    ssh_buffer_get_len(server_response));

    /* Add MSG_KEX_ECDH_REPLY header */
    rc = ssh_buffer_add_u8(session->out_buffer, SSH2_MSG_KEX_HYBRID_REPLY);
    if (rc < 0) {
        ssh_set_error_oom(session);
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    /* Get server host key */
    rc = ssh_get_key_params(session, &privkey, &digest);
    if (rc == SSH_ERROR) {
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    /* Build session ID */
    rc = ssh_make_sessionid(session);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Could not create a session id");
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    rc = ssh_dh_get_next_server_publickey_blob(session, &server_hostkey_blob);
    if (rc != 0) {
        ssh_set_error(session, SSH_FATAL, "Could not export server public key");
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    /* Add server host key to output */
    rc = ssh_buffer_add_ssh_string(session->out_buffer, server_hostkey_blob);
    SSH_STRING_FREE(server_hostkey_blob);
    if (rc < 0) {
        ssh_set_error_oom(session);
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    /* Add server response (ciphertext + pubkey) */
    rc = ssh_buffer_add_ssh_string(session->out_buffer, server_pubkey_blob);
    if (rc < 0) {
        ssh_set_error_oom(session);
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    /* Sign the exchange hash */
    sig_blob = ssh_srv_pki_do_sign_sessionid(session, privkey, digest);
    if (sig_blob == NULL) {
        ssh_set_error(session, SSH_FATAL, "Could not sign the session id");
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    /* Add signature */
    rc = ssh_buffer_add_ssh_string(session->out_buffer, sig_blob);
    SSH_STRING_FREE(sig_blob);
    if (rc < 0) {
        ssh_set_error_oom(session);
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    rc = ssh_packet_send(session);
    if (rc == SSH_ERROR) {
        ssh_set_error(session, SSH_FATAL, "Failed to send SSH_MSG_KEX_ECDH_REPLY");
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }

    /* Send the MSG_NEWKEYS */
    rc = ssh_packet_send_newkeys(session);
    if (rc == SSH_ERROR) {
        ssh_set_error(session, SSH_FATAL, "Failed to send SSH_MSG_NEWKEYS");
        session->session_state = SSH_SESSION_STATE_ERROR;
        goto cleanup;
    }
    session->dh_handshake_state = DH_STATE_NEWKEYS_SENT;

cleanup:
    /* Clear sensitive data */
    explicit_bzero(mlkem_shared_secret, sizeof(mlkem_shared_secret));
    explicit_bzero(curve25519_shared_secret, sizeof(curve25519_shared_secret));
    explicit_bzero(combined_secret, sizeof(combined_secret));
    explicit_bzero(hashed_secret, sizeof(hashed_secret));
    ssh_string_free(client_pubkey_blob);
    ssh_string_free(server_pubkey_blob);
    ssh_buffer_free(server_response);
    return SSH_PACKET_USED;
}

void ssh_server_mlkem768x25519_init(ssh_session session)
{
    SSH_LOG(SSH_LOG_TRACE, "Setting up ML-KEM768x25519 server callbacks");
    ssh_packet_set_callbacks(session, &ssh_mlkem768x25519_server_callbacks);
}

#endif /* WITH_SERVER */
