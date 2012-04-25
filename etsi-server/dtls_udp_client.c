
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define BUFFER_SIZE          (1<<16)
#define COOKIE_SECRET_LENGTH 16
char buf[BUFFER_SIZE];
SSL *ssl;

void dtls_start(char *remote_address, char *local_address, int port, int length, int messagenumber)
{
	int fd;
	char local_address_perkele[16];
	int i = 0;
//	int ind;
	int verbose = 1;
	int veryverbose = 1;

	struct sockaddr_in6 remote_addr;
	struct sockaddr_in6 local_addr;

	local_address_perkele[0] = 0x20;
	local_address_perkele[1] = 0x01;
	local_address_perkele[2] = 0x04;
	local_address_perkele[3] = 0x70;
	local_address_perkele[4] = 0x10;
	local_address_perkele[5] = 0x02;
	local_address_perkele[6] = 0x00;
	local_address_perkele[7] = 0x11;
	local_address_perkele[8] = 0x00;
	local_address_perkele[9] = 0x00;
	local_address_perkele[10] = 0x00;
	local_address_perkele[11] = 0x00;
	local_address_perkele[12] = 0x00;
	local_address_perkele[13] = 0x54;
	local_address_perkele[14] = 0x20;
	local_address_perkele[15] = 0x22;


	char buf[BUFFER_SIZE];
	char addrbuf[INET6_ADDRSTRLEN];
//	socklen_t len;
	SSL_CTX *ctx;
	BIO *bio;
	struct timeval timeout;

	//memset((void *) &remote_addr, 0, sizeof(struct sockaddr_in6));


	inet_pton(AF_INET6, local_address_perkele, &local_addr.sin6_addr);
	local_addr.sin6_family = AF_INET6;
	local_addr.sin6_port = htons(0);

	inet_pton(AF_INET6, (const char *)remote_address, (void *)&remote_addr.sin6_addr);
	remote_addr.sin6_family = AF_INET6;
	remote_addr.sin6_port = htons(port);


	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0)
	{
		perror("socket");
		exit(-1);
	}

//	inet_pton(AF_INET6, local_address, &local_addr.sin6_addr);
//	local_addr.sin6_family = AF_INET6;
//	local_addr.sin6_port = htons(0);

	bind(fd, (const struct sockaddr *) &local_addr, sizeof(struct sockaddr_in6));

	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(DTLSv1_client_method());
	SSL_CTX_set_cipher_list(ctx, "eNULL:!MD5");

	if (!SSL_CTX_use_certificate_file(ctx, "client-cert.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");

	if (!SSL_CTX_use_PrivateKey_file(ctx, "client-key.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key (ctx))
		printf("\nERROR: invalid private key!");

	SSL_CTX_set_verify_depth (ctx, 2);
	SSL_CTX_set_read_ahead(ctx, 1);

	ssl = SSL_new(ctx);

	/* Create BIO, connect and set to already connected */
	bio = BIO_new_dgram(fd, BIO_CLOSE);

	i = connect(fd, (struct sockaddr *) &remote_addr, sizeof(struct sockaddr_in6));

	printf("%d\n", i);

	//sleep(3);

//	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote_addr);

	SSL_set_bio(ssl, bio, bio);
	printf("1\n");
	if (SSL_connect(ssl) < 0)
	{
		perror("SSL_connect");
		printf("%s\n", ERR_error_string(ERR_get_error(), buf));
		exit(-1);
	}
	printf("2\n");
	fflush(stdout);
	/* Set and activate timeouts */
	timeout.tv_sec = 3;
	timeout.tv_usec = 0;
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

	if (verbose)
	{

		printf ("\nConnected to %s\n",
	   inet_ntop(AF_INET6, &remote_addr.sin6_addr, addrbuf, INET6_ADDRSTRLEN));
	}


	if (veryverbose && SSL_get_peer_certificate(ssl))
	{
		printf ("------------------------------------------------------------\n");
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)),
		                      1, XN_FLAG_MULTILINE);
		printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
		printf ("\n------------------------------------------------------------\n\n");
	}

	/*while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN))
	{
		if (messagenumber > 0)
		{
			len = SSL_write(ssl, buf, length);
			messagenumber --;
		}
	}*/
	}
