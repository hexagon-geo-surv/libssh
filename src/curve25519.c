/*
 * curve25519.c - Curve25519 ECDH functions for key exchange
 * curve25519-sha256@libssh.org and curve25519-sha256
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2013      by Aris Adamantiadis <aris@badcode.be>
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

#include "libssh/curve25519.h"
#ifdef HAVE_CURVE25519

#ifdef WITH_NACL
#include "nacl/crypto_scalarmult_curve25519.h"
#endif

#include "libssh/ssh2.h"
#include "libssh/buffer.h"
#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/crypto.h"
#include "libssh/dh.h"
#include "libssh/pki.h"
#include "libssh/bignum.h"

#ifdef HAVE_LIBCRYPTO
#include <openssl/err.h>
#elif defined(HAVE_MBEDTLS_CURVE25519)
#include "mbedcrypto-compat.h"
#include <mbedtls/ecdh.h>
#include <mbedtls/error.h>
#elif defined(HAVE_GCRYPT_CURVE25519)
#include <gcrypt.h>
#endif

static SSH_PACKET_CALLBACK(ssh_packet_client_curve25519_reply);

static ssh_packet_callback dh_client_callbacks[] = {
    ssh_packet_client_curve25519_reply
};

static struct ssh_packet_callbacks_struct ssh_curve25519_client_callbacks = {
    .start = SSH2_MSG_KEX_ECDH_REPLY,
    .n_callbacks = 1,
    .callbacks = dh_client_callbacks,
    .user = NULL
};

int ssh_curve25519_init(ssh_session session)
{
    ssh_curve25519_pubkey *pubkey_loc = NULL;

#ifdef HAVE_LIBCRYPTO
    int rc;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t pubkey_len = CURVE25519_PUBKEY_SIZE;

#elif defined(HAVE_MBEDTLS_CURVE25519)
    int rc;
    mbedtls_ecdh_context ecdh_ctx;
    mbedtls_ctr_drbg_context *ctr_drbg = NULL;
    char error_buf[128];
    int ret = SSH_ERROR;

#elif defined(HAVE_GCRYPT_CURVE25519)
    gcry_error_t gcry_err;
    gcry_sexp_t param = NULL, keypair_sexp = NULL;
    ssh_string privkey = NULL, pubkey = NULL;
    char *pubkey_data = NULL;
    int ret = SSH_ERROR;
#else
    int rc;
#endif

    if (session->server) {
        pubkey_loc = &session->next_crypto->curve25519_server_pubkey;
    } else {
        pubkey_loc = &session->next_crypto->curve25519_client_pubkey;
    }

#ifdef HAVE_LIBCRYPTO
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (pctx == NULL) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to initialize X25519 context: %s",
                ERR_error_string(ERR_get_error(), NULL));
        return SSH_ERROR;
    }

    rc = EVP_PKEY_keygen_init(pctx);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to initialize X25519 keygen: %s",
                ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_CTX_free(pctx);
        return SSH_ERROR;
    }

    rc = EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to generate X25519 keys: %s",
                ERR_error_string(ERR_get_error(), NULL));
        return SSH_ERROR;
    }

    rc = EVP_PKEY_get_raw_public_key(pkey, *pubkey_loc, &pubkey_len);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to get X25519 raw public key: %s",
                ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_free(pkey);
        return SSH_ERROR;
    }

    session->next_crypto->curve25519_privkey = pkey;
    pkey = NULL;

#elif defined(HAVE_MBEDTLS_CURVE25519)
    ctr_drbg = ssh_get_mbedtls_ctr_drbg_context();

    mbedtls_ecdh_init(&ecdh_ctx);
    rc = mbedtls_ecdh_setup(&ecdh_ctx, MBEDTLS_ECP_DP_CURVE25519);
    if (rc != 0) {
        mbedtls_strerror(rc, error_buf, sizeof(error_buf));
        SSH_LOG(SSH_LOG_TRACE, "Failed to setup X25519 context: %s", error_buf);
        goto out;
    }

#if MBEDTLS_VERSION_MAJOR > 2
    rc = mbedtls_ecdh_gen_public(&ecdh_ctx.MBEDTLS_PRIVATE(ctx)
                                      .MBEDTLS_PRIVATE(mbed_ecdh)
                                      .MBEDTLS_PRIVATE(grp),
                                 &ecdh_ctx.MBEDTLS_PRIVATE(ctx)
                                      .MBEDTLS_PRIVATE(mbed_ecdh)
                                      .MBEDTLS_PRIVATE(d),
                                 &ecdh_ctx.MBEDTLS_PRIVATE(ctx)
                                      .MBEDTLS_PRIVATE(mbed_ecdh)
                                      .MBEDTLS_PRIVATE(Q),
                                 mbedtls_ctr_drbg_random,
                                 ctr_drbg);
#else
    rc = mbedtls_ecdh_gen_public(&ecdh_ctx.grp,
                                 &ecdh_ctx.d,
                                 &ecdh_ctx.Q,
                                 mbedtls_ctr_drbg_random,
                                 ctr_drbg);
#endif
    if (rc != 0) {
        mbedtls_strerror(rc, error_buf, sizeof(error_buf));
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to generate X25519 keypair: %s",
                error_buf);
        goto out;
    }

#if MBEDTLS_VERSION_MAJOR > 2
    rc = mbedtls_mpi_write_binary_le(&ecdh_ctx.MBEDTLS_PRIVATE(ctx)
                                          .MBEDTLS_PRIVATE(mbed_ecdh)
                                          .MBEDTLS_PRIVATE(d),
                                     session->next_crypto->curve25519_privkey,
                                     CURVE25519_PRIVKEY_SIZE);
#else
    rc = mbedtls_mpi_write_binary_le(&ecdh_ctx.d,
                                     session->next_crypto->curve25519_privkey,
                                     CURVE25519_PRIVKEY_SIZE);
#endif
    if (rc != 0) {
        mbedtls_strerror(rc, error_buf, sizeof(error_buf));
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to write X25519 private key: %s",
                error_buf);
        goto out;
    }

#if MBEDTLS_VERSION_MAJOR > 2
    rc = mbedtls_mpi_write_binary_le(&ecdh_ctx.MBEDTLS_PRIVATE(ctx)
                                          .MBEDTLS_PRIVATE(mbed_ecdh)
                                          .MBEDTLS_PRIVATE(Q)
                                          .MBEDTLS_PRIVATE(X),
                                     *pubkey_loc,
                                     CURVE25519_PUBKEY_SIZE);
#else
    rc = mbedtls_mpi_write_binary_le(&ecdh_ctx.Q.X,
                                     *pubkey_loc,
                                     CURVE25519_PUBKEY_SIZE);
#endif
    if (rc != 0) {
        mbedtls_strerror(rc, error_buf, sizeof(error_buf));
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to write X25519 public key: %s",
                error_buf);
        goto out;
    }

    ret = SSH_OK;

out:
    mbedtls_ecdh_free(&ecdh_ctx);
    return ret;

#elif defined(HAVE_GCRYPT_CURVE25519)
    gcry_err =
        gcry_sexp_build(&param, NULL, "(genkey (ecdh (curve Curve25519)))");
    if (gcry_err != GPG_ERR_NO_ERROR) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to create keypair sexp: %s",
                gcry_strerror(gcry_err));
        goto out;
    }

    gcry_err = gcry_pk_genkey(&keypair_sexp, param);
    if (gcry_err != GPG_ERR_NO_ERROR) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to generate keypair: %s",
                gcry_strerror(gcry_err));
        goto out;
    }

    /* Extract the public key */
    pubkey = ssh_sexp_extract_mpi(keypair_sexp,
                                  "q",
                                  GCRYMPI_FMT_USG,
                                  GCRYMPI_FMT_STD);
    if (pubkey == NULL) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to extract public key: %s",
                gcry_strerror(gcry_err));
        goto out;
    }

    /* Store the public key in the session */
    /* The first byte should be 0x40 indicating that the point is compressed, so
     * we skip storing it */
    pubkey_data = (char *)ssh_string_data(pubkey);
    if (ssh_string_len(pubkey) != CURVE25519_PUBKEY_SIZE + 1 ||
        pubkey_data[0] != 0x40) {
        SSH_LOG(SSH_LOG_TRACE,
                "Invalid public key with length: %zu",
                ssh_string_len(pubkey));
        goto out;
    }

    memcpy(*pubkey_loc, pubkey_data + 1, CURVE25519_PUBKEY_SIZE);

    /* Store the private key */
    session->next_crypto->curve25519_privkey = keypair_sexp;
    keypair_sexp = NULL;
    ret = SSH_OK;

out:
    ssh_string_burn(privkey);
    SSH_STRING_FREE(privkey);
    ssh_string_burn(pubkey);
    SSH_STRING_FREE(pubkey);
    gcry_sexp_release(param);
    gcry_sexp_release(keypair_sexp);
    return ret;

#else
    rc = ssh_get_random(session->next_crypto->curve25519_privkey,
                        CURVE25519_PRIVKEY_SIZE, 1);
    if (rc != 1) {
        ssh_set_error(session, SSH_FATAL, "PRNG error");
        return SSH_ERROR;
    }

    crypto_scalarmult_base(*pubkey_loc,
                           session->next_crypto->curve25519_privkey);

#endif /* HAVE_LIBCRYPTO */

    return SSH_OK;
}

/** @internal
 * @brief Starts curve25519-sha256@libssh.org / curve25519-sha256 key exchange
 */
int ssh_client_curve25519_init(ssh_session session)
{
    int rc;

    rc = ssh_curve25519_init(session);
    if (rc != SSH_OK) {
        return rc;
    }

    rc = ssh_buffer_pack(session->out_buffer,
                         "bdP",
                         SSH2_MSG_KEX_ECDH_INIT,
                         CURVE25519_PUBKEY_SIZE,
                         (size_t)CURVE25519_PUBKEY_SIZE,
                         session->next_crypto->curve25519_client_pubkey);
    if (rc != SSH_OK) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }

    /* register the packet callbacks */
    ssh_packet_set_callbacks(session, &ssh_curve25519_client_callbacks);
    session->dh_handshake_state = DH_STATE_INIT_SENT;
    rc = ssh_packet_send(session);

    return rc;
}

void ssh_client_curve25519_remove_callbacks(ssh_session session)
{
    ssh_packet_remove_callbacks(session, &ssh_curve25519_client_callbacks);
}

int ssh_curve25519_create_k(ssh_session session, ssh_curve25519_pubkey k)
{
    ssh_curve25519_pubkey *peer_pubkey_loc = NULL;

#ifdef HAVE_LIBCRYPTO
    int rc, ret = SSH_ERROR;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL, *pubkey = NULL;
    size_t shared_key_len = CURVE25519_PUBKEY_SIZE;

#elif defined(HAVE_MBEDTLS_CURVE25519)
    int rc, ret = SSH_ERROR;
    mbedtls_ecdh_context ecdh_ctx;
    mbedtls_ctr_drbg_context *ctr_drbg = NULL;
    char error_buf[128];

#elif defined(HAVE_GCRYPT_CURVE25519)
    gcry_error_t gcry_err;
    gcry_sexp_t pubkey_sexp = NULL, privkey_data_sexp = NULL,
                result_sexp = NULL;
    ssh_string shared_secret = NULL, privkey = NULL;
    char *shared_secret_data = NULL;
    int ret = SSH_ERROR;

#endif
    if (session->server) {
        peer_pubkey_loc = &session->next_crypto->curve25519_client_pubkey;
    } else {
        peer_pubkey_loc = &session->next_crypto->curve25519_server_pubkey;
    }

#ifdef HAVE_LIBCRYPTO
    pkey = session->next_crypto->curve25519_privkey;
    if (pkey == NULL) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to create X25519 EVP_PKEY: %s",
                ERR_error_string(ERR_get_error(), NULL));
        return SSH_ERROR;
    }

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to initialize X25519 context: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }

    rc = EVP_PKEY_derive_init(pctx);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to initialize X25519 key derivation: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }

    pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519,
                                         NULL,
                                         *peer_pubkey_loc,
                                         CURVE25519_PUBKEY_SIZE);
    if (pubkey == NULL) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to create X25519 public key EVP_PKEY: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }

    rc = EVP_PKEY_derive_set_peer(pctx, pubkey);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to set peer X25519 public key: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }

    rc = EVP_PKEY_derive(pctx, k, &shared_key_len);
    if (rc != 1) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to derive X25519 shared secret: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }
    ret = SSH_OK;
out:
    EVP_PKEY_free(pubkey);
    EVP_PKEY_CTX_free(pctx);
    if (ret == SSH_ERROR) {
        return ret;
    }

#elif defined(HAVE_MBEDTLS_CURVE25519)
    ctr_drbg = ssh_get_mbedtls_ctr_drbg_context();

    mbedtls_ecdh_init(&ecdh_ctx);
    rc = mbedtls_ecdh_setup(&ecdh_ctx, MBEDTLS_ECP_DP_CURVE25519);
    if (rc != 0) {
        mbedtls_strerror(rc, error_buf, sizeof(error_buf));
        SSH_LOG(SSH_LOG_TRACE, "Failed to setup X25519 context: %s", error_buf);
        goto out;
    }

#if MBEDTLS_VERSION_MAJOR > 2
    rc = mbedtls_mpi_read_binary_le(&ecdh_ctx.MBEDTLS_PRIVATE(ctx)
                                         .MBEDTLS_PRIVATE(mbed_ecdh)
                                         .MBEDTLS_PRIVATE(d),
                                    session->next_crypto->curve25519_privkey,
                                    CURVE25519_PRIVKEY_SIZE);
#else
    rc = mbedtls_mpi_read_binary_le(&ecdh_ctx.d,
                                    session->next_crypto->curve25519_privkey,
                                    CURVE25519_PRIVKEY_SIZE);
#endif
    if (rc != 0) {
        mbedtls_strerror(rc, error_buf, sizeof(error_buf));
        SSH_LOG(SSH_LOG_TRACE, "Failed to read private key: %s", error_buf);
        goto out;
    }

#if MBEDTLS_VERSION_MAJOR > 2
    rc = mbedtls_mpi_read_binary_le(&ecdh_ctx.MBEDTLS_PRIVATE(ctx)
                                         .MBEDTLS_PRIVATE(mbed_ecdh)
                                         .MBEDTLS_PRIVATE(Qp)
                                         .MBEDTLS_PRIVATE(X),
                                    *peer_pubkey_loc,
                                    CURVE25519_PUBKEY_SIZE);
#else
    rc = mbedtls_mpi_read_binary_le(&ecdh_ctx.Qp.X,
                                    *peer_pubkey_loc,
                                    CURVE25519_PUBKEY_SIZE);
#endif
    if (rc != 0) {
        mbedtls_strerror(rc, error_buf, sizeof(error_buf));
        SSH_LOG(SSH_LOG_TRACE, "Failed to read peer public key: %s", error_buf);
        goto out;
    }

#if MBEDTLS_VERSION_MAJOR > 2
    rc = mbedtls_mpi_lset(&ecdh_ctx.MBEDTLS_PRIVATE(ctx)
                               .MBEDTLS_PRIVATE(mbed_ecdh)
                               .MBEDTLS_PRIVATE(Qp)
                               .MBEDTLS_PRIVATE(Z),
                          1);
#else
    rc = mbedtls_mpi_lset(&ecdh_ctx.Qp.Z, 1);
#endif
    if (rc != 0) {
        mbedtls_strerror(rc, error_buf, sizeof(error_buf));
        SSH_LOG(SSH_LOG_TRACE, "Failed to set Z coordinate: %s", error_buf);
        goto out;
    }

#if MBEDTLS_VERSION_MAJOR > 2
    rc = mbedtls_ecdh_compute_shared(&ecdh_ctx.MBEDTLS_PRIVATE(ctx)
                                          .MBEDTLS_PRIVATE(mbed_ecdh)
                                          .MBEDTLS_PRIVATE(grp),
                                     &ecdh_ctx.MBEDTLS_PRIVATE(ctx)
                                          .MBEDTLS_PRIVATE(mbed_ecdh)
                                          .MBEDTLS_PRIVATE(z),
                                     &ecdh_ctx.MBEDTLS_PRIVATE(ctx)
                                          .MBEDTLS_PRIVATE(mbed_ecdh)
                                          .MBEDTLS_PRIVATE(Qp),
                                     &ecdh_ctx.MBEDTLS_PRIVATE(ctx)
                                          .MBEDTLS_PRIVATE(mbed_ecdh)
                                          .MBEDTLS_PRIVATE(d),
                                     mbedtls_ctr_drbg_random,
                                     ctr_drbg);
#else
    rc = mbedtls_ecdh_compute_shared(&ecdh_ctx.grp,
                                     &ecdh_ctx.z,
                                     &ecdh_ctx.Qp,
                                     &ecdh_ctx.d,
                                     mbedtls_ctr_drbg_random,
                                     ctr_drbg);
#endif
    if (rc != 0) {
        mbedtls_strerror(rc, error_buf, sizeof(error_buf));
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to compute shared secret: %s",
                error_buf);
        goto out;
    }

#if MBEDTLS_VERSION_MAJOR > 2
    rc = mbedtls_mpi_write_binary_le(&ecdh_ctx.MBEDTLS_PRIVATE(ctx)
                                          .MBEDTLS_PRIVATE(mbed_ecdh)
                                          .MBEDTLS_PRIVATE(z),
                                     k,
                                     CURVE25519_PUBKEY_SIZE);
#else
    rc = mbedtls_mpi_write_binary_le(&ecdh_ctx.z, k, CURVE25519_PUBKEY_SIZE);
#endif
    if (rc != 0) {
        mbedtls_strerror(rc, error_buf, sizeof(error_buf));
        SSH_LOG(SSH_LOG_TRACE, "Failed to write shared secret: %s", error_buf);
        goto out;
    }

    ret = SSH_OK;

out:
    mbedtls_ecdh_free(&ecdh_ctx);
    if (ret == SSH_ERROR) {
        return ret;
    }

#elif defined(HAVE_GCRYPT_CURVE25519)
    gcry_err = gcry_sexp_build(
        &pubkey_sexp,
        NULL,
        "(key-data(public-key (ecdh (curve Curve25519) (q %b))))",
        CURVE25519_PUBKEY_SIZE,
        *peer_pubkey_loc);
    if (gcry_err != GPG_ERR_NO_ERROR) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to create peer public key sexp: %s",
                gcry_strerror(gcry_err));
        goto out;
    }

    privkey = ssh_sexp_extract_mpi(session->next_crypto->curve25519_privkey,
                                   "d",
                                   GCRYMPI_FMT_USG,
                                   GCRYMPI_FMT_STD);
    if (privkey == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Failed to extract private key");
        goto out;
    }

    gcry_err = gcry_sexp_build(&privkey_data_sexp,
                               NULL,
                               "(data(flags raw)(value %b))",
                               ssh_string_len(privkey),
                               ssh_string_data(privkey));
    if (gcry_err != GPG_ERR_NO_ERROR) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to create private key sexp: %s",
                gcry_strerror(gcry_err));
        goto out;
    }

    gcry_err = gcry_pk_encrypt(&result_sexp, privkey_data_sexp, pubkey_sexp);
    if (gcry_err != GPG_ERR_NO_ERROR) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to compute shared secret: %s",
                gcry_strerror(gcry_err));
        goto out;
    }

    shared_secret = ssh_sexp_extract_mpi(result_sexp,
                                         "s",
                                         GCRYMPI_FMT_USG,
                                         GCRYMPI_FMT_USG);
    if (shared_secret == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Failed to extract shared secret");
        goto out;
    }

    /* Copy the shared secret to the output buffer */
    /* The first byte should be 0x40 indicating that it is a compressed point,
     * so we skip it */
    shared_secret_data = (char *)ssh_string_data(shared_secret);
    if (ssh_string_len(shared_secret) != CURVE25519_PUBKEY_SIZE + 1 ||
        shared_secret_data[0] != 0x40) {
        SSH_LOG(SSH_LOG_TRACE,
                "Invalid shared secret with length: %zu",
                ssh_string_len(shared_secret));
        goto out;
    }

    memcpy(k, shared_secret_data + 1, CURVE25519_PUBKEY_SIZE);

    ret = SSH_OK;
    gcry_sexp_release(session->next_crypto->curve25519_privkey);
    session->next_crypto->curve25519_privkey = NULL;

out:
    ssh_string_burn(shared_secret);
    SSH_STRING_FREE(shared_secret);
    ssh_string_burn(privkey);
    SSH_STRING_FREE(privkey);
    gcry_sexp_release(privkey_data_sexp);
    gcry_sexp_release(pubkey_sexp);
    gcry_sexp_release(result_sexp);
    if (ret == SSH_ERROR) {
        return ret;
    }

#else
    crypto_scalarmult(k,
                      session->next_crypto->curve25519_privkey,
                      *peer_pubkey_loc);
#endif /* HAVE_LIBCRYPTO */

#ifdef DEBUG_CRYPTO
    ssh_log_hexdump("Session server cookie",
                    session->next_crypto->server_kex.cookie,
                    16);
    ssh_log_hexdump("Session client cookie",
                    session->next_crypto->client_kex.cookie,
                    16);
#endif

    return 0;
}

static int ssh_curve25519_build_k(ssh_session session)
{
    ssh_curve25519_pubkey k;
    int rc;

    rc = ssh_curve25519_create_k(session, k);
    if (rc != SSH_OK) {
        return rc;
    }

    bignum_bin2bn(k, CURVE25519_PUBKEY_SIZE, &session->next_crypto->shared_secret);
    if (session->next_crypto->shared_secret == NULL) {
        return SSH_ERROR;
    }

#ifdef DEBUG_CRYPTO
    ssh_print_bignum("Shared secret key", session->next_crypto->shared_secret);
#endif

    return 0;
}

/** @internal
 * @brief parses a SSH_MSG_KEX_ECDH_REPLY packet and sends back
 * a SSH_MSG_NEWKEYS
 */
static SSH_PACKET_CALLBACK(ssh_packet_client_curve25519_reply){
  ssh_string q_s_string = NULL;
  ssh_string pubkey_blob = NULL;
  ssh_string signature = NULL;
  int rc;
  (void)type;
  (void)user;

  ssh_client_curve25519_remove_callbacks(session);

  pubkey_blob = ssh_buffer_get_ssh_string(packet);
  if (pubkey_blob == NULL) {
    ssh_set_error(session,SSH_FATAL, "No public key in packet");
    goto error;
  }

  rc = ssh_dh_import_next_pubkey_blob(session, pubkey_blob);
  SSH_STRING_FREE(pubkey_blob);
  if (rc != 0) {
      ssh_set_error(session,
                    SSH_FATAL,
                    "Failed to import next public key");
      goto error;
  }

  q_s_string = ssh_buffer_get_ssh_string(packet);
  if (q_s_string == NULL) {
	  ssh_set_error(session,SSH_FATAL, "No Q_S ECC point in packet");
	  goto error;
  }
  if (ssh_string_len(q_s_string) != CURVE25519_PUBKEY_SIZE){
	  ssh_set_error(session, SSH_FATAL, "Incorrect size for server Curve25519 public key: %d",
			  (int)ssh_string_len(q_s_string));
	  SSH_STRING_FREE(q_s_string);
	  goto error;
  }
  memcpy(session->next_crypto->curve25519_server_pubkey, ssh_string_data(q_s_string), CURVE25519_PUBKEY_SIZE);
  SSH_STRING_FREE(q_s_string);

  signature = ssh_buffer_get_ssh_string(packet);
  if (signature == NULL) {
    ssh_set_error(session, SSH_FATAL, "No signature in packet");
    goto error;
  }
  session->next_crypto->dh_server_signature = signature;
  signature=NULL; /* ownership changed */
  /* TODO: verify signature now instead of waiting for NEWKEYS */
  if (ssh_curve25519_build_k(session) < 0) {
    ssh_set_error(session, SSH_FATAL, "Cannot build k number");
    goto error;
  }

  /* Send the MSG_NEWKEYS */
  rc = ssh_packet_send_newkeys(session);
  if (rc == SSH_ERROR) {
    goto error;
  }
  session->dh_handshake_state = DH_STATE_NEWKEYS_SENT;

  return SSH_PACKET_USED;

error:
  session->session_state=SSH_SESSION_STATE_ERROR;
  return SSH_PACKET_USED;
}

#ifdef WITH_SERVER

static SSH_PACKET_CALLBACK(ssh_packet_server_curve25519_init);

static ssh_packet_callback dh_server_callbacks[]= {
    ssh_packet_server_curve25519_init
};

static struct ssh_packet_callbacks_struct ssh_curve25519_server_callbacks = {
    .start = SSH2_MSG_KEX_ECDH_INIT,
    .n_callbacks = 1,
    .callbacks = dh_server_callbacks,
    .user = NULL
};

/** @internal
 * @brief sets up the curve25519-sha256@libssh.org kex callbacks
 */
void ssh_server_curve25519_init(ssh_session session){
    /* register the packet callbacks */
    ssh_packet_set_callbacks(session, &ssh_curve25519_server_callbacks);
}

/** @brief Parse a SSH_MSG_KEXDH_INIT packet (server) and send a
 * SSH_MSG_KEXDH_REPLY
 */
static SSH_PACKET_CALLBACK(ssh_packet_server_curve25519_init){
    /* ECDH keys */
    ssh_string q_c_string = NULL;
    ssh_string q_s_string = NULL;
    ssh_string server_pubkey_blob = NULL;

    /* SSH host keys (rsa, ed25519 and ecdsa) */
    ssh_key privkey = NULL;
    enum ssh_digest_e digest = SSH_DIGEST_AUTO;
    ssh_string sig_blob = NULL;
    int rc;
    (void)type;
    (void)user;

    ssh_packet_remove_callbacks(session, &ssh_curve25519_server_callbacks);

    /* Extract the client pubkey from the init packet */
    q_c_string = ssh_buffer_get_ssh_string(packet);
    if (q_c_string == NULL) {
        ssh_set_error(session,SSH_FATAL, "No Q_C ECC point in packet");
        goto error;
    }
    if (ssh_string_len(q_c_string) != CURVE25519_PUBKEY_SIZE){
        ssh_set_error(session,
                      SSH_FATAL,
                      "Incorrect size for server Curve25519 public key: %zu",
                      ssh_string_len(q_c_string));
        goto error;
    }

    memcpy(session->next_crypto->curve25519_client_pubkey,
           ssh_string_data(q_c_string), CURVE25519_PUBKEY_SIZE);
    SSH_STRING_FREE(q_c_string);

    /* Build server's key pair */
    rc = ssh_curve25519_init(session);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Failed to generate curve25519 keys");
        goto error;
    }

    rc = ssh_buffer_add_u8(session->out_buffer, SSH2_MSG_KEX_ECDH_REPLY);
    if (rc < 0) {
        ssh_set_error_oom(session);
        goto error;
    }

    /* build k and session_id */
    rc = ssh_curve25519_build_k(session);
    if (rc < 0) {
        ssh_set_error(session, SSH_FATAL, "Cannot build k number");
        goto error;
    }

    /* privkey is not allocated */
    rc = ssh_get_key_params(session, &privkey, &digest);
    if (rc == SSH_ERROR) {
        goto error;
    }

    rc = ssh_make_sessionid(session);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Could not create a session id");
        goto error;
    }

    rc = ssh_dh_get_next_server_publickey_blob(session, &server_pubkey_blob);
    if (rc != 0) {
        ssh_set_error(session, SSH_FATAL, "Could not export server public key");
        goto error;
    }

    /* add host's public key */
    rc = ssh_buffer_add_ssh_string(session->out_buffer,
                                   server_pubkey_blob);
    SSH_STRING_FREE(server_pubkey_blob);
    if (rc < 0) {
        ssh_set_error_oom(session);
        goto error;
    }

    /* add ecdh public key */
    q_s_string = ssh_string_new(CURVE25519_PUBKEY_SIZE);
    if (q_s_string == NULL) {
        ssh_set_error_oom(session);
        goto error;
    }

    rc = ssh_string_fill(q_s_string,
                         session->next_crypto->curve25519_server_pubkey,
                         CURVE25519_PUBKEY_SIZE);
    if (rc < 0) {
        ssh_set_error(session, SSH_FATAL, "Could not copy public key");
        goto error;
    }

    rc = ssh_buffer_add_ssh_string(session->out_buffer, q_s_string);
    SSH_STRING_FREE(q_s_string);
    if (rc < 0) {
        ssh_set_error_oom(session);
        goto error;
    }
    /* add signature blob */
    sig_blob = ssh_srv_pki_do_sign_sessionid(session, privkey, digest);
    if (sig_blob == NULL) {
        ssh_set_error(session, SSH_FATAL, "Could not sign the session id");
        goto error;
    }

    rc = ssh_buffer_add_ssh_string(session->out_buffer, sig_blob);
    SSH_STRING_FREE(sig_blob);
    if (rc < 0) {
        ssh_set_error_oom(session);
        goto error;
    }

    SSH_LOG(SSH_LOG_DEBUG, "SSH_MSG_KEX_ECDH_REPLY sent");
    rc = ssh_packet_send(session);
    if (rc == SSH_ERROR) {
        return SSH_ERROR;
    }

    session->dh_handshake_state = DH_STATE_NEWKEYS_SENT;

    /* Send the MSG_NEWKEYS */
    rc = ssh_packet_send_newkeys(session);
    if (rc == SSH_ERROR) {
        goto error;
    }

    return SSH_PACKET_USED;
error:
    SSH_STRING_FREE(q_c_string);
    SSH_STRING_FREE(q_s_string);
    ssh_buffer_reinit(session->out_buffer);
    session->session_state=SSH_SESSION_STATE_ERROR;
    return SSH_PACKET_USED;
}

#endif /* WITH_SERVER */

#endif /* HAVE_CURVE25519 */
