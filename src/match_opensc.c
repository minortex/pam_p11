#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/*
 * Check that the opened file is owned by the given user and is not
 * world-writable.  Returns 1 if safe, 0 otherwise.
 */
static int check_file_owner(int fd, const struct passwd *pw)
{
	struct stat st;

	if (0 != fstat(fd, &st))
		return 0;
	/* Must be a regular file */
	if (!S_ISREG(st.st_mode))
		return 0;
	/* Must be owned by the target user or by root */
	if (st.st_uid != pw->pw_uid && st.st_uid != 0)
		return 0;
	/* Must not be group-writable or world-writable */
	if (st.st_mode & (S_IWGRP | S_IWOTH))
		return 0;
	return 1;
}

extern int match_user_opensc(EVP_PKEY *authkey, const char *login,
		const char *file_path)
{
	char filename[PATH_MAX];
	struct passwd *pw;
	int found;
	int fd;
	BIO *in;
	X509 *cert = NULL;

	if (NULL == authkey || NULL == login)
		return -1;

	pw = getpwnam(login);
	if (!pw || !pw->pw_dir)
		return -1;

	if (file_path && file_path[0]) {
		snprintf(filename, sizeof filename, "%s", file_path);
	} else {
		snprintf(filename, sizeof filename,
				"%s/.eid/authorized_certificates", pw->pw_dir);
	}

	/* Open with O_NOFOLLOW + fstat to avoid TOCTOU, then use
	 * BIO_new_fd to wrap the checked fd. */
	fd = open(filename, O_RDONLY | O_NOFOLLOW);
	if (fd < 0) {
		syslog(LOG_ERR, "open authorized certificates file "
					"failed for %s\n", login);
		return -1;
	}

	if (!check_file_owner(fd, pw)) {
		syslog(LOG_ERR, "unsafe ownership on authorized "
					"certificates file for %s\n", login);
		close(fd);
		return -1;
	}

	/* BIO_new_fd with close_flag=1 takes ownership of fd */
	in = BIO_new_fd(fd, 1);
	if (!in) {
		close(fd);
		return -1;
	}

	found = 0;
	do {
		EVP_PKEY *key;
		if (NULL == PEM_read_bio_X509(in, &cert, 0, NULL)) {
			break;
		}
		key = X509_get_pubkey(cert);
		if (key == NULL)
			continue;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
		if (1 == EVP_PKEY_cmp(authkey, key)) {
			found = 1;
		}
#else
		if (1 == EVP_PKEY_eq(authkey, key)) {
			found = 1;
		}
#endif
		EVP_PKEY_free(key);
	} while (found == 0);

	if (cert) {
		X509_free(cert);
	}

	BIO_free(in);

	return found;
}
