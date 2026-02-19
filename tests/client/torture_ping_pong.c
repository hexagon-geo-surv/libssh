/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2026 by Shreyas Mahajan <shreyasmahajan05@gmail.com>
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

/*
 * This test validates the OpenSSH ping@openssh.com extension against a
 * real OpenSSH server by:
 * 1. Connecting a libssh client to an OpenSSH server
 * 2. Verifying the server advertises ping@openssh.com extension support
 * 3. Sending PING packets from the client to the server
 * 4. Verifying the client receives PONG responses with correct payload
 */

#include "config.h"

#define LIBSSH_STATIC

#include <errno.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "libssh/buffer.h"
#include "libssh/callbacks.h"
#include "libssh/libssh.h"
#include "libssh/packet.h"
#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/ssh2.h"
#include "torture.h"

/* State for PONG callback */
struct test_ping_state {
    int pong_count;
    ssh_buffer pong_payload;
};

/* Session callback to handle PONG messages */
static void pong_session_callback(ssh_session session,
                                  const void *payload,
                                  size_t payload_len,
                                  void *user)
{
    struct test_ping_state *pstate = user;

    (void)session;

    if (pstate->pong_payload == NULL) {
        pstate->pong_payload = ssh_buffer_new();
    } else {
        ssh_buffer_reinit(pstate->pong_payload);
    }

    if (pstate->pong_payload != NULL && payload_len > 0 && payload != NULL) {
        (void)ssh_buffer_add_data(pstate->pong_payload, payload, payload_len);
    }

    pstate->pong_count++;
}

static void register_pong_callback(ssh_session session,
                                   struct test_ping_state *pstate,
                                   struct ssh_callbacks_struct *pong_cb)
{
    int rc;

    assert_non_null(pong_cb);

    memset(pong_cb, 0, sizeof(*pong_cb));
    pong_cb->userdata = pstate;
    pong_cb->pong_function = pong_session_callback;
    ssh_callbacks_init(pong_cb);

    rc = ssh_set_callbacks(session, pong_cb);
    assert_int_equal(rc, SSH_OK);
}

static void send_ping_and_expect_pong(ssh_session session,
                                      ssh_event event,
                                      struct test_ping_state *pstate,
                                      const void *ping_payload,
                                      size_t ping_payload_len,
                                      int expected_count)
{
    const void *payload_data = NULL;
    size_t payload_len = 0;
    int rc;
    int i;

    rc = ssh_send_ping(session, ping_payload, ping_payload_len);
    assert_int_equal(rc, SSH_OK);

    for (i = 0; i < 20; i++) {
        rc = ssh_event_dopoll(event, 100);
        if (rc == SSH_ERROR) {
            fprintf(stderr, "Event poll error: %s\n", ssh_get_error(session));
            assert_int_not_equal(rc, SSH_ERROR);
        }

        if (pstate->pong_count >= expected_count) {
            break;
        }
    }

    if (pstate->pong_count < expected_count) {
        fail_msg("Timed out waiting for PONG #%d after %d event polls",
                 expected_count,
                 i);
    }

    assert_non_null(pstate->pong_payload);

    payload_len = ssh_buffer_get_len(pstate->pong_payload);
    payload_data = ssh_buffer_get(pstate->pong_payload);

    assert_int_equal(payload_len, ping_payload_len);
    if (ping_payload_len > 0) {
        assert_non_null(payload_data);
        assert_memory_equal(payload_data, ping_payload, ping_payload_len);
    }
}

static int sshd_setup(void **state)
{
    torture_setup_sshd_server(state, false);

    return 0;
}

static int sshd_teardown(void **state)
{
    torture_teardown_sshd_server(state);

    return 0;
}

static int session_setup(void **state)
{
    struct torture_state *s = *state;
    struct passwd *pwd = NULL;
    int rc;

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = torture_ssh_session(s,
                                         TORTURE_SSH_SERVER,
                                         NULL,
                                         TORTURE_SSH_USER_ALICE,
                                         NULL);
    assert_non_null(s->ssh.session);

    return 0;
}

static int session_teardown(void **state)
{
    struct torture_state *s = *state;

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

/**
 * Test basic ping/pong functionality against OpenSSH server
 * Verifies:
 * - Extension is advertised
 * - PING can be sent
 * - PONG is received with correct payload
 */
static void torture_ping_pong_basic(void **state)
{
    struct torture_state *s = *state;
    struct test_ping_state pstate = {0, NULL};
    struct ssh_callbacks_struct pong_cb;
    ssh_session session = s->ssh.session;
    ssh_event event = NULL;
    const char *test_data = "Hello OpenSSH!";
    int rc;

    /* Check if server supports ping extension */
    if (!ssh_is_ping_supported(session)) {
        skip();
    }

    /* Set up event loop */
    event = ssh_event_new();
    assert_non_null(event);

    rc = ssh_event_add_session(event, session);
    assert_int_equal(rc, SSH_OK);

    /* Register PONG callback */
    register_pong_callback(session, &pstate, &pong_cb);

    send_ping_and_expect_pong(session,
                              event,
                              &pstate,
                              test_data,
                              strlen(test_data),
                              1);

    ssh_event_free(event);
    SSH_BUFFER_FREE(pstate.pong_payload);
}

/**
 * Test multiple ping/pong exchanges
 * Verifies that multiple PING/PONG exchanges work correctly
 */
static void torture_ping_pong_multiple(void **state)
{
    struct torture_state *s = *state;
    struct test_ping_state pstate = {0, NULL};
    struct ssh_callbacks_struct pong_cb;
    ssh_session session = s->ssh.session;
    ssh_event event = NULL;
    const char *test_messages[] = {"First ping", "Second ping", "Third ping"};
    size_t num_pings = ARRAY_SIZE(test_messages);
    int rc;
    size_t j;

    /* Check if server supports ping extension */
    if (!ssh_is_ping_supported(session)) {
        fprintf(
            stderr,
            "Server does not support ping@openssh.com extension (multiple)\n");
        skip();
    }

    /* Set up event loop */
    event = ssh_event_new();
    assert_non_null(event);

    rc = ssh_event_add_session(event, session);
    assert_int_equal(rc, SSH_OK);

    /* Register PONG callback */
    register_pong_callback(session, &pstate, &pong_cb);

    /* Send multiple PINGs and verify each PONG */
    for (j = 0; j < num_pings; j++) {
        const char *msg = test_messages[j];
        int expected_count = (int)j + 1;

        send_ping_and_expect_pong(session,
                                  event,
                                  &pstate,
                                  msg,
                                  strlen(msg),
                                  expected_count);
    }

    /* Verify we received all PONGs */
    assert_int_equal(pstate.pong_count, (int)num_pings);

    ssh_event_free(event);
    SSH_BUFFER_FREE(pstate.pong_payload);
}

/**
 * Test that no extra PONG messages are received beyond the number of sent
 * PING messages in normal client/server operation.
 */
static void torture_ping_pong_no_extra_pongs(void **state)
{
    struct torture_state *s = *state;
    struct test_ping_state pstate = {0, NULL};
    struct ssh_callbacks_struct pong_cb;
    ssh_session session = s->ssh.session;
    ssh_event event = NULL;
    int rc;
    int i;
    int sent_pings = 2;

    if (!ssh_is_ping_supported(session)) {
        skip();
    }

    event = ssh_event_new();
    assert_non_null(event);

    rc = ssh_event_add_session(event, session);
    assert_int_equal(rc, SSH_OK);

    register_pong_callback(session, &pstate, &pong_cb);

    rc = ssh_send_ping(session, "one", 3);
    assert_int_equal(rc, SSH_OK);
    rc = ssh_send_ping(session, "two", 3);
    assert_int_equal(rc, SSH_OK);

    for (i = 0; i < 20; i++) {
        rc = ssh_event_dopoll(event, 100);
        assert_int_not_equal(rc, SSH_ERROR);

        if (pstate.pong_count >= sent_pings) {
            break;
        }
    }

    assert_int_equal(pstate.pong_count, sent_pings);

    /* Keep polling to verify no extra unsolicited PONG appears. */
    for (i = 0; i < 10; i++) {
        rc = ssh_event_dopoll(event, 50);
        assert_int_not_equal(rc, SSH_ERROR);
    }

    assert_int_equal(pstate.pong_count, sent_pings);

    ssh_event_free(event);
    SSH_BUFFER_FREE(pstate.pong_payload);
}

/**
 * Test that sending PING after disconnect fails.
 */
static void torture_ping_pong_send_after_disconnect(void **state)
{
    struct torture_state *s = *state;
    ssh_session session = s->ssh.session;
    int rc;

    if (!ssh_is_ping_supported(session)) {
        skip();
    }

    ssh_disconnect(session);

    rc = ssh_send_ping(session, "after-disconnect", 16);
    assert_int_equal(rc, SSH_ERROR);
}

/**
 * Test PING with empty payload
 * Verifies that PING with no data works correctly
 */
static void torture_ping_pong_empty(void **state)
{
    struct torture_state *s = *state;
    struct test_ping_state pstate = {0, NULL};
    struct ssh_callbacks_struct pong_cb;
    ssh_session session = s->ssh.session;
    ssh_event event = NULL;
    int rc;

    /* Check if server supports ping extension */
    if (!ssh_is_ping_supported(session)) {
        fprintf(stderr,
                "Server does not support ping@openssh.com extension (empty)\n");
        skip();
    }

    /* Set up event loop */
    event = ssh_event_new();
    assert_non_null(event);

    rc = ssh_event_add_session(event, session);
    assert_int_equal(rc, SSH_OK);

    /* Register PONG callback */
    register_pong_callback(session, &pstate, &pong_cb);

    send_ping_and_expect_pong(session, event, &pstate, NULL, 0, 1);

    ssh_event_free(event);
    SSH_BUFFER_FREE(pstate.pong_payload);
}

static void torture_send_ping_null_session(UNUSED_PARAM(void **state))
{
    int rc;

    rc = ssh_send_ping(NULL, NULL, 0);
    assert_int_equal(rc, SSH_ERROR);
}

static void torture_is_ping_supported_null_session(UNUSED_PARAM(void **state))
{
    bool rc;

    rc = ssh_is_ping_supported(NULL);
    assert_false(rc);
}

static void
torture_is_ping_supported_extension_state(UNUSED_PARAM(void **state))
{
    ssh_session session = NULL;

    session = ssh_new();
    assert_non_null(session);

    session->extensions &= ~SSH_EXT_PING;
    assert_false(ssh_is_ping_supported(session));

    session->extensions |= SSH_EXT_PING;
    assert_true(ssh_is_ping_supported(session));

    ssh_free(session);
}

static void torture_send_ping_no_extension(UNUSED_PARAM(void **state))
{
    ssh_session session = NULL;
    int rc;

    session = ssh_new();
    assert_non_null(session);

    rc = ssh_send_ping(session, "hello", 5);
    assert_int_equal(rc, SSH_ERROR);

    assert_int_not_equal(session->session_state, SSH_SESSION_STATE_ERROR);

    ssh_free(session);
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_ping_pong_basic,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_ping_pong_multiple,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_ping_pong_no_extra_pongs,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_ping_pong_empty,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test_setup_teardown(torture_ping_pong_send_after_disconnect,
                                        session_setup,
                                        session_teardown),
        cmocka_unit_test(torture_send_ping_null_session),
        cmocka_unit_test(torture_is_ping_supported_null_session),
        cmocka_unit_test(torture_is_ping_supported_extension_state),
        cmocka_unit_test(torture_send_ping_no_extension),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, sshd_setup, sshd_teardown);

    ssh_finalize();

    return rc;
}
