/*
 * Copyright 2026 libssh authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define LIBSSH_STATIC 1
#include <libssh/libssh.h>
#include <libssh/scp.h>

#include "nallocinc.c"
#include "ssh_server_mock.h"

static void _fuzz_finalize(void)
{
    ssh_finalize();
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    nalloc_init(*argv[0]);
    ssh_init();
    atexit(_fuzz_finalize);
    ssh_mock_write_hostkey(SSH_MOCK_HOSTKEY_PATH);
    return 0;
}

static const char *const k_ciphers[] = {
    "none",
    "aes128-ctr",
    "aes256-ctr",
    "aes128-cbc",
};

static const char *const k_hmacs[] = {
    "none",
    "hmac-sha1",
    "hmac-sha2-256",
};

/*
 * Wrap fuzzer bytes as a valid SCP server record stream so the client
 * survives ssh_scp_init's initial-ACK gate and reaches the deeper SCP
 * code paths (record parsing, accept/deny, transfer flow, recursive
 * push). Without this wrapping the fuzzer almost never satisfies the
 * "\x00C<mode> <size> <name>\n" prefix the SCP layer expects, and
 * coverage stalls in the early-protocol record-parser rejection paths.
 *
 * The 4 envelope bytes consumed here are still fuzzer-controlled, so
 * libFuzzer mutations explore C/D/T/E variants, mismatched sizes, and
 * unusual modes from inside the wrap:
 *
 *   data[0..1]  SCP mode (12 bits)
 *   data[2]     bit 0-1: variant select (0=C, 1=D, 2=T, 3=E)
 *               bit 2:   optional trailing server-ACK after payload
 *   data[3]     declared transfer size in the C-record header
 *   data[4..]   raw payload bytes appended after the SCP header
 *
 * Coverage of invalid SCP record parsing is NOT given up by this
 * shaping: ssh_server_fuzzer and ssh_client_fuzzer pump unstructured
 * bytes through the SSH transport and reach the SCP record parser's
 * rejection paths from that direction.
 */
static size_t
scp_wrap(const uint8_t *data, size_t size, uint8_t *out, size_t out_cap)
{
    uint16_t mode;
    uint8_t variant;
    uint8_t declared_size;
    size_t payload_sz;
    size_t cap_left;
    size_t total;
    int n;

    if (size < 4 || out_cap == 0) {
        return 0;
    }
    mode = ((uint16_t)data[0] << 8 | data[1]) & 07777;
    variant = data[2] & 0x03;
    declared_size = data[3];

    switch (variant) {
    case 0:
        n = snprintf((char *)out,
                     out_cap,
                     "%cC%04o %u f\n",
                     0,
                     mode,
                     declared_size);
        break;
    case 1:
        n = snprintf((char *)out, out_cap, "%cD%04o 0 d\n", 0, mode);
        break;
    case 2:
        n = snprintf((char *)out, out_cap, "%cT0 0 0 0\n", 0);
        break;
    default:
        n = snprintf((char *)out, out_cap, "%cE\n", 0);
        break;
    }
    if (n < 0 || (size_t)n >= out_cap) {
        return 0;
    }

    payload_sz = size - 4;
    cap_left = out_cap - (size_t)n;
    if (payload_sz > cap_left) {
        payload_sz = cap_left;
    }
    memcpy(out + n, data + 4, payload_sz);
    total = (size_t)n + payload_sz;
    /* Optional server final ACK; bit chosen by fuzzer to cover both paths */
    if (variant == 0 && (data[2] & 0x04) && total < out_cap) {
        out[total++] = '\x00';
    }
    return total;
}

/* Run one SCP fuzzing iteration against the mock server */
static int test_scp_with_cipher(const uint8_t *data,
                                size_t size,
                                const char *cipher,
                                const char *hmac)
{
    bool thread_started = false;
    int socket_fds[2] = {-1, -1};
    ssh_session client_session = NULL;
    ssh_scp scp = NULL, scp_recursive = NULL;
    char buf[256] = {0};
    pthread_t srv_thread;
    int rc;
    long timeout = 1;
    bool no = false;
    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};

    /* Configure mock SSH server with fuzzer data */
    struct ssh_mock_server_config server_config = {
        .protocol_data = data,
        .protocol_data_size = size,
        .exec_callback = ssh_mock_send_raw_data,
        .subsystem_callback = NULL,
        .callback_userdata = NULL,
        .cipher = cipher,
        .hmac = hmac,
        .server_socket = -1,
        .client_socket = -1,
        .server_ready = false,
        .server_error = false,
        .shutdown_requested = false,
    };

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socket_fds) != 0) {
        goto cleanup;
    }

    /* Set socket timeouts to prevent indefinite blocking */
    setsockopt(socket_fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(socket_fds[0], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(socket_fds[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(socket_fds[1], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    server_config.server_socket = socket_fds[0];
    server_config.client_socket = socket_fds[1];

    if (ssh_mock_server_start(&server_config, &srv_thread) != 0) {
        goto cleanup;
    }
    thread_started = true;

    client_session = ssh_new();
    if (client_session == NULL) {
        goto cleanup;
    }

    /* Configure client; bail on the first failing option-set so we don't
     * run the rest of the iteration in a partially-configured state.
     * SSH_OPTIONS_PROCESS_CONFIG is set to false so the fuzzer doesn't read
     * ~/.ssh/config or /etc/ssh/ssh_config — keeps results deterministic
     * across environments. SSH_OPTIONS_TIMEOUT is 1 second. */
    rc = ssh_options_set(client_session, SSH_OPTIONS_FD, &socket_fds[1]);
    if (rc != SSH_OK) {
        goto cleanup;
    }
    rc = ssh_options_set(client_session, SSH_OPTIONS_HOST, "localhost");
    if (rc != SSH_OK) {
        goto cleanup;
    }
    rc = ssh_options_set(client_session, SSH_OPTIONS_USER, "fuzz");
    if (rc != SSH_OK) {
        goto cleanup;
    }
    rc = ssh_options_set(client_session, SSH_OPTIONS_CIPHERS_C_S, cipher);
    if (rc != SSH_OK) {
        goto cleanup;
    }
    rc = ssh_options_set(client_session, SSH_OPTIONS_CIPHERS_S_C, cipher);
    if (rc != SSH_OK) {
        goto cleanup;
    }
    rc = ssh_options_set(client_session, SSH_OPTIONS_HMAC_C_S, hmac);
    if (rc != SSH_OK) {
        goto cleanup;
    }
    rc = ssh_options_set(client_session, SSH_OPTIONS_HMAC_S_C, hmac);
    if (rc != SSH_OK) {
        goto cleanup;
    }
    rc = ssh_options_set(client_session, SSH_OPTIONS_PROCESS_CONFIG, &no);
    if (rc != SSH_OK) {
        goto cleanup;
    }
    rc = ssh_options_set(client_session, SSH_OPTIONS_TIMEOUT, &timeout);
    if (rc != SSH_OK) {
        goto cleanup;
    }

    if (ssh_connect(client_session) != SSH_OK) {
        goto cleanup;
    }

    if (ssh_userauth_none(client_session, NULL) != SSH_AUTH_SUCCESS) {
        goto cleanup;
    }

    scp = ssh_scp_new(client_session, SSH_SCP_READ, "/tmp/fuzz");
    if (scp == NULL) {
        goto cleanup;
    }

    if (ssh_scp_init(scp) != SSH_OK) {
        goto cleanup;
    }

    if (size > 0) {
        size_t copy_size = size < sizeof(buf) ? size : sizeof(buf);
        memcpy(buf, data, copy_size);
    }

    /* Fuzz all SCP API functions in read mode */
    ssh_scp_pull_request(scp);
    ssh_scp_request_get_filename(scp);
    ssh_scp_request_get_permissions(scp);
    ssh_scp_request_get_size64(scp);
    ssh_scp_request_get_size(scp);
    ssh_scp_request_get_warning(scp);
    ssh_scp_accept_request(scp);
    ssh_scp_deny_request(scp, "Denied by fuzzer");
    ssh_scp_read(scp, buf, sizeof(buf));

    /* Final fuzz of scp pull request after all the calls */
    ssh_scp_pull_request(scp);

    /* Fuzz SCP in write/upload + recursive directory mode. */
    scp_recursive = ssh_scp_new(client_session,
                                SSH_SCP_WRITE | SSH_SCP_RECURSIVE,
                                "/tmp/fuzz-recursive");
    if (scp_recursive != NULL) {
        if (ssh_scp_init(scp_recursive) == SSH_OK) {
            ssh_scp_push_directory(scp_recursive, "fuzz-dir", 0755);
            ssh_scp_push_file(scp_recursive, "fuzz-file", sizeof(buf), 0644);
            ssh_scp_write(scp_recursive, buf, sizeof(buf));
            ssh_scp_leave_directory(scp_recursive);
        }
    }

cleanup:
    /* Signal server thread to exit */
    server_config.shutdown_requested = true;

    /* Close sockets */
    if (socket_fds[0] >= 0)
        close(socket_fds[0]);
    if (socket_fds[1] >= 0)
        close(socket_fds[1]);

    /* Cleanup client objects */
    if (scp_recursive != NULL) {
        ssh_scp_close(scp_recursive);
        ssh_scp_free(scp_recursive);
    }
    if (scp) {
        ssh_scp_close(scp);
        ssh_scp_free(scp);
    }
    if (client_session) {
        ssh_disconnect(client_session);
        ssh_free(client_session);
    }

    /* Server thread exits via shutdown_requested + 2s socket timeout */
    if (thread_started) {
        pthread_join(srv_thread, NULL);
    }

    return 0;
}

/*
 * Fuzzer input layout (not passed directly to the SSH transport; it is
 * decoded here, then fed through scp_wrap):
 *
 *   data[0]   cipher index, taken modulo length of k_ciphers
 *   data[1]   HMAC index,   taken modulo length of k_hmacs
 *   data[2..] handed to scp_wrap, which uses the first 4 bytes as the
 *             SCP envelope (mode, variant, declared size, optional ACK
 *             toggle) and the rest as the file-content payload.
 *
 * Inputs shorter than 6 bytes are rejected so every iteration has at
 * least the two selector bytes plus one full envelope for scp_wrap.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t wrapped[4096];
    size_t wrapped_size = 0;
    const char *cipher = NULL;
    const char *hmac = NULL;

    if (size < 6) {
        return 0;
    }

    assert(nalloc_start(data, size) > 0);

    cipher = k_ciphers[data[0] % (sizeof(k_ciphers) / sizeof(k_ciphers[0]))];
    hmac = k_hmacs[data[1] % (sizeof(k_hmacs) / sizeof(k_hmacs[0]))];

    wrapped_size = scp_wrap(data + 2, size - 2, wrapped, sizeof(wrapped));
    if (wrapped_size > 0) {
        test_scp_with_cipher(wrapped, wrapped_size, cipher, hmac);
    }

    nalloc_end();
    return 0;
}
