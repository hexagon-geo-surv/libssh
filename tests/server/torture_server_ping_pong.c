/*
 * torture_server_ping_pong.c - server-side test for SSH ping/pong extension
 * (RFC PROTOCOL)
 *
 * This test validates the OpenSSH ping@openssh.com extension by:
 * 1. Starting a libssh server instance (via test_server infrastructure)
 * 2. Connecting a client to the server
 * 3. Verifying the server advertises ping@openssh.com extension support
 * 4. Sending a PING packet from the client to the server
 * 5. Verifying the client receives a PONG response
 *
 * Note: We only test from the client's perspective since the test_server
 * runs in a separate process and we cannot observe its internal state.
 */

#include "config.h"

#define LIBSSH_STATIC

#include <errno.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
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

/* Reuse the same server infrastructure as torture_server_default.c */
#include "test_server.h"
#include "default_cb.h"

struct test_server_ping_pong_state {
    struct torture_state *state;
    int client_pong_count;
    ssh_buffer client_pong_payload;
    struct ssh_callbacks_struct client_pong_callbacks;
};

static void client_pong_cb(ssh_session session,
                           const void *payload,
                           size_t payload_len,
                           void *user)
{
    struct test_server_ping_pong_state *t =
        (struct test_server_ping_pong_state *)user;

    (void)session;

    if (t == NULL) {
        return;
    }

    if (t->client_pong_payload == NULL) {
        t->client_pong_payload = ssh_buffer_new();
    } else {
        ssh_buffer_reinit(t->client_pong_payload);
    }

    if (t->client_pong_payload != NULL && payload_len > 0 && payload != NULL) {
        (void)ssh_buffer_add_data(t->client_pong_payload, payload, payload_len);
    }

    t->client_pong_count++;
}

static void register_client_pong_callback(ssh_session session,
                                          struct test_server_ping_pong_state *t)
{
    int rc;

    assert_non_null(t);

    ssh_callbacks_init(&t->client_pong_callbacks);
    t->client_pong_callbacks.userdata = t;
    t->client_pong_callbacks.pong_function = client_pong_cb;

    rc = ssh_set_callbacks(session, &t->client_pong_callbacks);
    assert_int_equal(rc, SSH_OK);
}

static int server_setup(void **state)
{
    struct test_server_ping_pong_state *t = NULL;
    struct torture_state *s = NULL;

    t = calloc(1, sizeof(struct test_server_ping_pong_state));
    assert_non_null(t);

    torture_setup_socket_dir((void **)&s);
    torture_setup_create_libssh_config((void **)&s);

    torture_setup_libssh_server((void **)&s, "./test_server/test_server");
    assert_non_null(s);

    t->state = s;
    *state = t;

    return 0;
}

static int server_teardown(void **state)
{
    struct test_server_ping_pong_state *t = *state;
    struct torture_state *s = NULL;

    assert_non_null(t);

    s = t->state;
    assert_non_null(s);

    torture_teardown_sshd_server((void **)&s);
    SAFE_FREE(t);

    return 0;
}

static int session_setup(void **state)
{
    struct test_server_ping_pong_state *t = *state;
    struct torture_state *s = NULL;
    struct passwd *pwd = NULL;
    int verbosity = torture_libssh_verbosity();
    bool b = false;
    int rc;

    assert_non_null(t);
    s = t->state;
    assert_non_null(s);

    SSH_BUFFER_FREE(t->client_pong_payload);
    t->client_pong_count = 0;

    unsetenv("SSH_AUTH_SOCK");

    pwd = getpwnam("bob");
    assert_non_null(pwd);

    rc = setuid(pwd->pw_uid);
    assert_return_code(rc, errno);

    s->ssh.session = ssh_new();
    assert_non_null(s->ssh.session);

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    assert_ssh_return_code(s->ssh.session, rc);

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    assert_ssh_return_code(s->ssh.session, rc);

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_PROCESS_CONFIG, &b);
    assert_ssh_return_code(s->ssh.session, rc);

    return 0;
}

static int session_teardown(void **state)
{
    struct test_server_ping_pong_state *t = *state;
    struct torture_state *s = NULL;

    assert_non_null(t);
    s = t->state;
    assert_non_null(s);

    SSH_BUFFER_FREE(t->client_pong_payload);

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);

    return 0;
}

static void torture_server_ping_pong(void **state)
{
    struct test_server_ping_pong_state *t = *state;
    struct torture_state *s = NULL;
    ssh_session session = NULL;
    ssh_event event = NULL;
    const char *test_data = "test ping data";
    int rc;
    int i;

    assert_non_null(t);
    s = t->state;
    assert_non_null(s);

    session = s->ssh.session;
    assert_non_null(session);

    assert_int_equal(t->client_pong_count, 0);
    assert_null(t->client_pong_payload);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_userauth_none(session, NULL);
    assert_true(rc == SSH_AUTH_DENIED || rc == SSH_AUTH_SUCCESS);

    assert_true(ssh_is_ping_supported(session));

    event = ssh_event_new();
    assert_non_null(event);

    rc = ssh_event_add_session(event, session);
    assert_int_equal(rc, SSH_OK);

    register_client_pong_callback(session, t);

    /* Send first PING with some test data */
    rc = ssh_send_ping(session, test_data, strlen(test_data));
    assert_int_equal(rc, SSH_OK);

    for (i = 0; i < 20; i++) {
        rc = ssh_event_dopoll(event, 100);
        assert_int_not_equal(rc, SSH_ERROR);

        if (t->client_pong_count >= 1) {
            break;
        }
    }

    if (t->client_pong_count < 1) {
        fail_msg("Timed out waiting for first PONG after %d event polls", i);
    }

    /* Verify the first PONG payload matches the PING data */
    assert_non_null(t->client_pong_payload);
    {
        size_t pong_len = ssh_buffer_get_len(t->client_pong_payload);
        const void *pong_data = ssh_buffer_get(t->client_pong_payload);

        assert_int_equal(pong_len, strlen(test_data));
        assert_memory_equal(pong_data, test_data, strlen(test_data));
    }

    /* Send second PING to test the cleanup code path in the callback */
    rc = ssh_send_ping(session, test_data, strlen(test_data));
    assert_int_equal(rc, SSH_OK);

    for (i = 0; i < 20; i++) {
        rc = ssh_event_dopoll(event, 100);
        assert_int_not_equal(rc, SSH_ERROR);

        if (t->client_pong_count >= 2) {
            break;
        }
    }

    if (t->client_pong_count < 2) {
        fail_msg("Timed out waiting for second PONG after %d event polls", i);
    }

    /* Verify the second PONG payload matches the PING data */
    assert_non_null(t->client_pong_payload);
    {
        size_t pong_len = ssh_buffer_get_len(t->client_pong_payload);
        const void *pong_data = ssh_buffer_get(t->client_pong_payload);

        assert_int_equal(pong_len, strlen(test_data));
        assert_memory_equal(pong_data, test_data, strlen(test_data));
    }

    /* Verify we received exactly 2 PONGs */
    assert_int_equal(t->client_pong_count, 2);

    ssh_event_free(event);
}

int torture_run_tests(void)
{
    int rc;

    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_server_ping_pong,
                                        session_setup,
                                        session_teardown),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, server_setup, server_teardown);
    ssh_finalize();

    return rc;
}
