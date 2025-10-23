/*
 * torture_sk.c - torture library for testing security keys
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2025 Praneeth Sarode <praneethsarode@gmail.com>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
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

#include "torture_sk.h"
#include "libssh/pki.h"
#include "libssh/sk_api.h" /* For SSH_SK_* flag definitions */

void assert_sk_key_valid(ssh_key key,
                         enum ssh_keytypes_e expected_type,
                         bool private)
{
    char *app_str = NULL;
    const char *expected_type_str = NULL;

    assert_non_null(key);
    assert_true(is_sk_key_type(expected_type));
    assert_int_equal(key->type, expected_type);

    if (private) {
        assert_int_equal(key->flags,
                         SSH_KEY_FLAG_PRIVATE | SSH_KEY_FLAG_PUBLIC);
    } else {
        assert_int_equal(key->flags, SSH_KEY_FLAG_PUBLIC);
    }

    expected_type_str = ssh_key_type_to_char(expected_type);
    assert_non_null(expected_type_str);

    assert_non_null(key->type_c);
    assert_string_equal(key->type_c, expected_type_str);

    /* Validate security key specific fields */
    assert_non_null(key->sk_application);

    /* Validate application string format and content */
    app_str = ssh_string_to_char(key->sk_application);
    assert_non_null(app_str);

    assert_true(ssh_string_len(key->sk_application) >= 4);
    assert_true(strncmp(app_str, "ssh:", 4) == 0);
    ssh_string_free_char(app_str);

    if (private) {
        assert_non_null(key->sk_key_handle);
        assert_true(ssh_string_len(key->sk_key_handle) > 0);
    }

    const uint8_t allowed_flags = SSH_SK_USER_PRESENCE_REQD |
                                  SSH_SK_USER_VERIFICATION_REQD |
                                  SSH_SK_RESIDENT_KEY | SSH_SK_FORCE_OPERATION;

    /* Validate sk_flags contain only allowed bits */
    uint8_t flags = key->sk_flags;
    assert_int_equal(flags & ~allowed_flags, 0);

    /* Validate underlying cryptographic key exists based on type */
    switch (expected_type) {
    case SSH_KEYTYPE_SK_ECDSA:
#if defined(HAVE_LIBGCRYPT)
        assert_non_null(key->ecdsa);
#elif defined(HAVE_LIBMBEDCRYPTO)
        assert_non_null(key->ecdsa);
#elif defined(HAVE_LIBCRYPTO)
        assert_non_null(key->key);
#endif
        break;

    case SSH_KEYTYPE_SK_ED25519:
#if defined(HAVE_LIBCRYPTO)
        assert_non_null(key->key);
#elif !defined(HAVE_LIBCRYPTO)
        assert_non_null(key->ed25519_pubkey);
#endif
        break;

    default:
        /* Should not reach here */
        assert_true(0);
        break;
    }
}

void assert_sk_enroll_response(struct sk_enroll_response *response, int flags)
{
    assert_non_null(response);

    assert_non_null(response->public_key);
    assert_true(response->public_key_len > 0);

    assert_non_null(response->key_handle);
    assert_true(response->key_handle_len > 0);

    assert_non_null(response->signature);
    assert_true(response->signature_len > 0);

    /*
     * This check might fail for some authenticators, as returning an
     * attestation certificate as part of the attestation statement is not
     * mandated by the FIDO2 standard.
     */
    assert_non_null(response->attestation_cert);
    assert_true(response->attestation_cert_len > 0);

    assert_non_null(response->authdata);
    assert_true(response->authdata_len > 0);

    assert_int_equal(response->flags, flags);
}

void assert_sk_sign_response(struct sk_sign_response *response,
                             enum ssh_keytypes_e key_type)
{
    assert_non_null(response);

    assert_non_null(response->sig_r);
    assert_true(response->sig_r_len > 0);

    /* sig_s is NULL for Ed25519, present for ECDSA */
    switch (key_type) {
    case SSH_SK_ECDSA:
        assert_non_null(response->sig_s);
        assert_true(response->sig_s_len > 0);
        break;
    case SSH_SK_ED25519:
        assert_null(response->sig_s);
        assert_int_equal(response->sig_s_len, 0);
        break;
    default:
        /* Should not reach here */
        assert_true(0);
        break;
    }
}

void assert_sk_resident_key(struct sk_resident_key *resident_key)
{
    assert_non_null(resident_key);

    assert_non_null(resident_key->application);
    assert_true(strlen(resident_key->application) > 0);

    assert_non_null(resident_key->user_id);
    assert_true(resident_key->user_id_len > 0);

    assert_non_null(resident_key->key.public_key);
    assert_true(resident_key->key.public_key_len > 0);

    assert_non_null(resident_key->key.key_handle);
    assert_true(resident_key->key.key_handle_len > 0);
}

const char *torture_get_sk_pin(void)
{
    const char *pin = getenv("TORTURE_SK_PIN");
    return (pin != NULL && pin[0] != '\0') ? pin : NULL;
}

#ifdef HAVE_SK_DUMMY

/* External declarations for sk-dummy library functions
 * These match the signatures in openssh sk-api.h */
extern uint32_t sk_api_version(void);

extern int sk_enroll(uint32_t alg,
                     const uint8_t *challenge,
                     size_t challenge_len,
                     const char *application,
                     uint8_t flags,
                     const char *pin,
                     struct sk_option **options,
                     struct sk_enroll_response **enroll_response);

extern int sk_sign(uint32_t alg,
                   const uint8_t *data,
                   size_t data_len,
                   const char *application,
                   const uint8_t *key_handle,
                   size_t key_handle_len,
                   uint8_t flags,
                   const char *pin,
                   struct sk_option **options,
                   struct sk_sign_response **sign_response);

extern int sk_load_resident_keys(const char *pin,
                                 struct sk_option **options,
                                 struct sk_resident_key ***resident_keys,
                                 size_t *num_keys_found);

static struct ssh_sk_callbacks_struct sk_dummy_callbacks = {
    .api_version = sk_api_version,
    .enroll = sk_enroll,
    .sign = sk_sign,
    .load_resident_keys = sk_load_resident_keys,
};

#endif /* HAVE_SK_DUMMY */

#ifdef WITH_FIDO2

const struct ssh_sk_callbacks_struct *torture_get_sk_dummy_callbacks(void)
{
#ifdef HAVE_SK_DUMMY
    ssh_callbacks_init(&sk_dummy_callbacks);
    return &sk_dummy_callbacks;
#else
    return NULL;
#endif /* HAVE_SK_DUMMY */
}

const struct ssh_sk_callbacks_struct *torture_get_sk_callbacks(void)
{
    const char *env = getenv("TORTURE_SK_USBHID");
    bool torture_sk_usbhid = (env != NULL && env[0] != '\0');

    if (torture_sk_usbhid) {
        return ssh_sk_get_default_callbacks();
    } else {
        return torture_get_sk_dummy_callbacks();
    }
}

#endif /* WITH_FIDO2 */

bool torture_sk_is_using_sk_dummy(void)
{
    const char *env = getenv("TORTURE_SK_USBHID");
    /* Return true if using sk-dummy callbacks (when TORTURE_SK_USBHID is NOT
     * set) */
    return (env == NULL || env[0] == '\0');
}
