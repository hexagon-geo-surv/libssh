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
#include "torture.h"

/* Helper function to validate ssh_key structure for security keys */
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

    /* TODO: Check for sk_flags */

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
