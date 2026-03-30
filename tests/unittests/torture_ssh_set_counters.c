#include "config.h"
#define LIBSSH_STATIC
#include "torture.h"
#include "torture_key.h"
#include <errno.h>
#include <libssh/libssh.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#define TEST_SERVER_HOST "127.0.0.1"
#define TEST_SERVER_PORT 2223

struct hostkey_state {
    const char *hostkey;
    char *hostkey_path;
    enum ssh_keytypes_e key_type;
    int fd;
};

struct counter_state {
    struct ssh_counter_struct scounter;
    struct ssh_counter_struct rcounter;
};

static int setup(void **state)
{
    struct hostkey_state *h = NULL;
    mode_t mask;
    int rc;

    ssh_threads_set_callbacks(ssh_threads_get_pthread());
    rc = ssh_init();
    if (rc != SSH_OK) {
        return -1;
    }

    h = malloc(sizeof(struct hostkey_state));
    assert_non_null(h);

    h->hostkey_path = strdup("/tmp/libssh_hostkey_XXXXXX");
    assert_non_null(h->hostkey_path);

    mask = umask(S_IRWXO | S_IRWXG);
    h->fd = mkstemp(h->hostkey_path);
    umask(mask);
    assert_return_code(h->fd, errno);
    close(h->fd);

    h->key_type = SSH_KEYTYPE_ECDSA_P256;
    h->hostkey = torture_get_testkey(h->key_type, 0);
    torture_write_file(h->hostkey_path, h->hostkey);

    *state = h;
    return 0;
}

static int teardown(void **state)
{
    struct hostkey_state *h = (struct hostkey_state *)*state;

    unlink(h->hostkey_path);
    free(h->hostkey_path);
    free(h);

    ssh_finalize();
    return 0;
}

static void *client_thread(void *arg)
{
    unsigned int test_port = TEST_SERVER_PORT;
    struct counter_state *cs = (struct counter_state *)arg;
    ssh_session session = NULL;
    bool process_config = false;
    int method, rc = SSH_AUTH_ERROR;

    session = ssh_new();
    assert_non_null(session);

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, TEST_SERVER_HOST);
    assert_int_equal(rc, SSH_OK);
    rc = ssh_options_set(session, SSH_OPTIONS_PORT, &test_port);
    assert_int_equal(rc, SSH_OK);
    rc = ssh_options_set(session, SSH_OPTIONS_USER, "foo");
    assert_int_equal(rc, SSH_OK);
    rc = ssh_options_set(session, SSH_OPTIONS_PROCESS_CONFIG, &process_config);
    assert_int_equal(rc, SSH_OK);

    /* Attach counters BEFORE connecting */
    ssh_set_counters(session, &cs->scounter, &cs->rcounter);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_userauth_none(session, NULL);
    if (rc == SSH_ERROR) {
        goto cleanup;
    }

    method = ssh_userauth_list(session, NULL);
    if (method & SSH_AUTH_METHOD_PASSWORD) {
        rc = ssh_userauth_password(session, NULL, "bar");
    }
    assert_int_equal(rc, SSH_AUTH_SUCCESS);

cleanup:
    ssh_disconnect(session);
    ssh_free(session);

    return NULL;
}

static int auth_password_accept(ssh_session session,
                                const char *user,
                                const char *password,
                                void *userdata)
{
    (void)session;
    (void)user;
    (void)password;
    (void)userdata;

    return SSH_AUTH_SUCCESS;
}

static void torture_ssh_set_counters_null(void **state)
{
    (void)state;

    /* Should not crash with NULL session */
    ssh_set_counters(NULL, NULL, NULL);
}

static void torture_ssh_set_counters_traffic(void **state)
{
    struct hostkey_state *h = (struct hostkey_state *)*state;
    struct counter_state cs = {
        .scounter = {0},
        .rcounter = {0},
    };
    pthread_t client_pthread;
    ssh_bind sshbind = NULL;
    ssh_session server = NULL;
    ssh_event event = NULL;
    int rc, event_rc;

    struct ssh_server_callbacks_struct server_cb = {
        .auth_password_function = auth_password_accept,
    };
    ssh_callbacks_init(&server_cb);

    sshbind = torture_ssh_bind(TEST_SERVER_HOST,
                               TEST_SERVER_PORT,
                               h->key_type,
                               h->hostkey_path);
    assert_non_null(sshbind);

    server = ssh_new();
    assert_non_null(server);

    /* Start client thread */
    rc = pthread_create(&client_pthread, NULL, client_thread, &cs);
    assert_return_code(rc, errno);

    rc = ssh_bind_accept(sshbind, server);
    assert_int_equal(rc, SSH_OK);

    ssh_set_server_callbacks(server, &server_cb);

    rc = ssh_handle_key_exchange(server);
    assert_int_equal(rc, SSH_OK);

    event = ssh_event_new();
    assert_non_null(event);
    rc = ssh_event_add_session(event, server);
    assert_int_equal(rc, SSH_OK);

    /* Poll until client disconnects */
    do {
        event_rc = ssh_event_dopoll(event, 100);
    } while (event_rc == SSH_OK);

    rc = pthread_join(client_pthread, NULL);
    assert_int_equal(rc, 0);

    /* Verify socket counters were incremented */
    assert_true(cs.scounter.in_bytes > 0);
    assert_true(cs.scounter.out_bytes > 0);

    /* Verify raw counters were incremented */
    assert_true(cs.rcounter.in_bytes > 0);
    assert_true(cs.rcounter.out_bytes > 0);
    assert_true(cs.rcounter.in_packets > 0);
    assert_true(cs.rcounter.out_packets > 0);

    ssh_event_free(event);
    ssh_free(server);
    ssh_bind_free(sshbind);
}

int torture_run_tests(void)
{
    int rc;
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_ssh_set_counters_null),
        cmocka_unit_test_setup_teardown(torture_ssh_set_counters_traffic,
                                        setup,
                                        teardown),
    };

    rc = cmocka_run_group_tests(tests, NULL, NULL);
    return rc;
}
