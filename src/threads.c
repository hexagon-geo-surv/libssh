/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2010 by Aris Adamantiadis
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

/**
 * @defgroup libssh_threads Threading with libssh
 * @ingroup libssh
 *
 * Threading with libssh
 * @{
 */

#include "libssh/priv.h"
#include "libssh/threads.h"

static int threads_noop (void **lock){
	(void)lock;
  return 0;
}

static unsigned long threads_id_noop (void){
	return 1;
}

struct ssh_threads_callbacks_struct ssh_threads_noop =
{
		.type="threads_noop",
    .mutex_init=threads_noop,
    .mutex_destroy=threads_noop,
    .mutex_lock=threads_noop,
    .mutex_unlock=threads_noop,
    .thread_id=threads_id_noop
};

static struct ssh_threads_callbacks_struct *user_callbacks;

#ifdef HAVE_LIBGCRYPT

/* Libgcrypt specific way of handling thread callbacks */

static struct gcry_thread_cbs gcrypt_threads_callbacks;

static int libgcrypt_thread_init(void){
	if(user_callbacks == NULL)
		return SSH_ERROR;
	if(user_callbacks == &ssh_threads_noop){
		gcrypt_threads_callbacks.option= GCRY_THREAD_OPTION_VERSION << 8 || GCRY_THREAD_OPTION_DEFAULT;
	} else {
		gcrypt_threads_callbacks.option= GCRY_THREAD_OPTION_VERSION << 8 || GCRY_THREAD_OPTION_USER;
	}
	gcrypt_threads_callbacks.mutex_init=user_callbacks->mutex_init;
	gcrypt_threads_callbacks.mutex_destroy=user_callbacks->mutex_destroy;
	gcrypt_threads_callbacks.mutex_lock=user_callbacks->mutex_lock;
	gcrypt_threads_callbacks.mutex_unlock=user_callbacks->mutex_unlock;
	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcrypt_threads_callbacks);
	return SSH_OK;
}
#else

/* Libcrypto specific stuff */

void **libcrypto_mutexes;

static void libcrypto_lock_callback(int mode, int i, const char *file, int line){
	(void)file;
	(void)line;
	if(mode & CRYPTO_LOCK){
		user_callbacks->mutex_lock(&libcrypto_mutexes[i]);
	} else {
		user_callbacks->mutex_unlock(&libcrypto_mutexes[i]);
	}
}

static int libcrypto_thread_init(){
	int n=CRYPTO_num_locks();
	int i;
	if(user_callbacks == &ssh_threads_noop)
		return SSH_OK;
	libcrypto_mutexes=malloc(sizeof(void *) * n);
	if (libcrypto_mutexes == NULL)
		return SSH_ERROR;
	for (i=0;i<n;++i){
		user_callbacks->mutex_init(&libcrypto_mutexes[i]);
	}
  CRYPTO_set_id_callback(user_callbacks->thread_id);
	CRYPTO_set_locking_callback(libcrypto_lock_callback);

	return SSH_OK;
}

static void libcrypto_thread_finalize(){
	int n=CRYPTO_num_locks();
	int i;
	if (libcrypto_mutexes==NULL)
		return;
	for (i=0;i<n;++i){
			user_callbacks->mutex_destroy(&libcrypto_mutexes[i]);
	}
	SAFE_FREE(libcrypto_mutexes);

}

#endif

/** @internal
 * @brief inits the threading with the backend cryptographic libraries
 */

int ssh_threads_init(void){
	static int threads_initialized=0;
	int ret;
	if(threads_initialized)
		return SSH_OK;
	/* first initialize the user_callbacks with our default handlers if not
	 * already the case
	 */
	if(user_callbacks == NULL){
		user_callbacks=&ssh_threads_noop;
	}

	/* Then initialize the crypto libraries threading callbacks */
#ifdef HAVE_LIBGCRYPT
	ret = libgcrypt_thread_init();
#else /* Libcrypto */
	ret = libcrypto_thread_init();
#endif
	if(ret == SSH_OK)
		threads_initialized=1;
  return ret;
}

void ssh_threads_finalize(void){
#ifdef HAVE_LIBGCRYPT
#else
	libcrypto_thread_finalize();
#endif
}

int ssh_threads_set_callbacks(struct ssh_threads_callbacks_struct *cb){
  user_callbacks=cb;
  return SSH_OK;
}

/**
 * @}
 */
