/*
 * Copyright 2025 Jakub Jelen <jjelen@redhat.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LIBSSH_STATIC 1
#include "libssh/libssh.h"

static void _fuzz_finalize(void)
{
    ssh_finalize();
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;

    ssh_init();

    atexit(_fuzz_finalize);

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ssh_key pkey = NULL;
    const char input[] = "badc0de";
    const char namespace[] = "namespace";
    char *signature = NULL;
    int rc;

    signature = (char *)malloc(size + 1);
    if (signature == NULL) {
        return 1;
    }
    strncpy(signature, (const char *)data, size);
    signature[size] = '\0';

    rc = sshsig_verify(input, sizeof(input), signature, namespace, &pkey);
    free(signature);
    if (rc != SSH_OK) {
        return 1;
    }
    ssh_key_free(pkey);

    return 0;
}
