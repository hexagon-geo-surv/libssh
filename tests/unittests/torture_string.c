/*
 * torture_string.c - torture tests for ssh_string functions
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

#include "config.h"

#include <errno.h>
#include <string.h>

#define LIBSSH_STATIC

#include "libssh/string.h"
#include "string.c"
#include "torture.h"

static void torture_ssh_string_new(void **state)
{
    struct ssh_string_struct *str = NULL;

    (void)state;

    /* Test normal allocation */
    str = ssh_string_new(100);
    assert_non_null(str);
    assert_int_equal(ssh_string_len(str), 100);
    ssh_string_free(str);

    /* Test zero size */
    str = ssh_string_new(0);
    assert_non_null(str);
    assert_int_equal(ssh_string_len(str), 0);
    ssh_string_free(str);

    /* Test maximum size */
    str = ssh_string_new(STRING_SIZE_MAX - 1);
    assert_non_null(str);
    assert_int_equal(ssh_string_len(str), STRING_SIZE_MAX - 1);
    ssh_string_free(str);

    /* Test size too large - should fail */
    str = ssh_string_new(STRING_SIZE_MAX + 1);
    assert_null(str);
    assert_int_equal(errno, EINVAL);
}

static void torture_ssh_string_from_char(void **state)
{
    struct ssh_string_struct *str = NULL;
    const char *test_string = "Hello, World!";
    const char *empty_string = "";

    (void)state;

    /* Test normal string */
    str = ssh_string_from_char(test_string);
    assert_non_null(str);
    assert_int_equal(ssh_string_len(str), strlen(test_string));
    assert_memory_equal(ssh_string_data(str), test_string, strlen(test_string));
    ssh_string_free(str);

    /* Test empty string */
    str = ssh_string_from_char(empty_string);
    assert_non_null(str);
    assert_int_equal(ssh_string_len(str), 0);
    ssh_string_free(str);

    /* Test NULL input */
    str = ssh_string_from_char(NULL);
    assert_null(str);
    assert_int_equal(errno, EINVAL);
}

static void torture_ssh_string_fill(void **state)
{
    struct ssh_string_struct *str = NULL;
    const char *test_data = "Test data";
    int rc;

    (void)state;

    /* Test normal fill */
    str = ssh_string_new(20);
    assert_non_null(str);

    rc = ssh_string_fill(str, test_data, strlen(test_data));
    assert_int_equal(rc, 0);
    assert_memory_equal(ssh_string_data(str), test_data, strlen(test_data));
    ssh_string_free(str);

    /* Test fill with exact size */
    str = ssh_string_new(strlen(test_data));
    assert_non_null(str);

    rc = ssh_string_fill(str, test_data, strlen(test_data));
    assert_int_equal(rc, 0);
    ssh_string_free(str);

    /* Test NULL data */
    str = ssh_string_new(10);
    assert_non_null(str);

    rc = ssh_string_fill(str, NULL, 5);
    assert_int_equal(rc, -1);
    ssh_string_free(str);

    /* Test zero length */
    str = ssh_string_new(10);
    assert_non_null(str);

    rc = ssh_string_fill(str, test_data, 0);
    assert_int_equal(rc, -1);
    ssh_string_free(str);
}

static void torture_ssh_string_to_char(void **state)
{
    struct ssh_string_struct *str = NULL;
    const char *test_string = "Convert to char";
    char *result = NULL;

    (void)state;

    /* Test normal string */
    str = ssh_string_from_char(test_string);
    assert_non_null(str);

    result = ssh_string_to_char(str);
    assert_non_null(result);
    assert_string_equal(result, test_string);

    ssh_string_free_char(result);
    ssh_string_free(str);

    /* Test empty string */
    str = ssh_string_from_char("");
    assert_non_null(str);

    result = ssh_string_to_char(str);
    assert_non_null(result);
    assert_string_equal(result, "");

    ssh_string_free_char(result);
    ssh_string_free(str);

    /* Test NULL string */
    result = ssh_string_to_char(NULL);
    assert_null(result);
}

static void torture_ssh_string_copy(void **state)
{
    struct ssh_string_struct *str = NULL, *copy = NULL;
    const char *test_string = "Copy me!";

    (void)state;

    /* Test normal copy */
    str = ssh_string_from_char(test_string);
    assert_non_null(str);

    copy = ssh_string_copy(str);
    assert_non_null(copy);
    assert_int_equal(ssh_string_len(copy), ssh_string_len(str));
    assert_memory_equal(ssh_string_data(copy),
                        ssh_string_data(str),
                        ssh_string_len(str));

    /* Ensure they are different objects */
    assert_ptr_not_equal(str, copy);
    assert_ptr_not_equal(ssh_string_data(str), ssh_string_data(copy));

    ssh_string_free(str);
    ssh_string_free(copy);

    /* Test copy of empty string */
    str = ssh_string_from_char("");
    assert_non_null(str);

    copy = ssh_string_copy(str);
    assert_non_null(copy);
    assert_int_equal(ssh_string_len(copy), 0);

    ssh_string_free(str);
    ssh_string_free(copy);

    /* Test NULL string */
    copy = ssh_string_copy(NULL);
    assert_null(copy);
}

static void torture_ssh_string_burn(void **state)
{
    struct ssh_string_struct *str = NULL;
    const char *test_string = "Secret data";
    void *data = NULL;
    size_t len;
    int i;

    (void)state;

    /* Test burning a string */
    str = ssh_string_from_char(test_string);
    assert_non_null(str);

    data = ssh_string_data(str);
    len = ssh_string_len(str);

    /* Verify data is there initially */
    assert_memory_equal(data, test_string, len);

    /* Burn the string */
    ssh_string_burn(str);

    /* Verify data is zeroed out */
    for (i = 0; i < (int)len; i++) {
        assert_int_equal(((unsigned char *)data)[i], 0);
    }

    ssh_string_free(str);

    /* Test burning NULL string (should not crash) */
    ssh_string_burn(NULL);

    /* Test burning zero-size string */
    str = ssh_string_new(0);
    assert_non_null(str);
    ssh_string_burn(str);
    ssh_string_free(str);
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_ssh_string_new),
        cmocka_unit_test(torture_ssh_string_from_char),
        cmocka_unit_test(torture_ssh_string_fill),
        cmocka_unit_test(torture_ssh_string_to_char),
        cmocka_unit_test(torture_ssh_string_copy),
        cmocka_unit_test(torture_ssh_string_burn),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();

    return rc;
}
