/*
 * DTLSProxy.cpp
 *
 *  Created on: Oct 12, 2011
 *      Author: Mikko
 */

#include "DTLSProxy.hpp"

#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

using namespace std;

int cookie_initialized=0;
#define COOKIE_SECRET_LENGTH 16
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];

DTLSProxy::DTLSProxy(int dtlsport, int port, string local_addr, string nsp_addr) {
	this->dtlsport = dtlsport;
	this->port = port;

	this->local_addr_str = local_addr;
	this->nsp_addr_str = nsp_addr;
}

DTLSProxy::~DTLSProxy() {
	// TODO Auto-generated destructor stub
}

int dtls_verify_callback (int ok, X509_STORE_CTX *ctx) {
	/* This function should ask the user
	 * if he trusts the received certificate.
	 * Here we always trust.
	 */
	return 1;
}


int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
	{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;

	/* Initialize a random secret */
	if (!cookie_initialized)
		{
		if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH))
			{
			printf("error setting random cookie secret\n");
			return 0;
			}
		cookie_initialized = 1;
		}

	/* Read peer information */
//	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
(int)BIO_ctrl(SSL_get_rbio(ssl), 46, 0, (char *)&peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		case AF_INET6:
			length += sizeof(struct in6_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
		{
		printf("out of memory\n");
		return 0;
		}

	switch (peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer,
			       &peer.s4.sin_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(peer.s4.sin_port),
			       &peer.s4.sin_addr,
			       sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(buffer,
			       &peer.s6.sin6_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
			       &peer.s6.sin6_addr,
			       sizeof(struct in6_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
	     (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

	return 1;
}


int verify_cookie(SSL *ssl, unsigned char *cookie, unsigned int cookie_len)
	{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;

	/* If secret isn't initialized yet, the cookie can't be valid */
	if (!cookie_initialized)
		return 0;

	/* Read peer information */
//	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
(int)BIO_ctrl(SSL_get_rbio(ssl), 46, 0, (char *)&peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		case AF_INET6:
			length += sizeof(struct in6_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
		{
		printf("out of memory\n");
		return 0;
		}

	switch (peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer,
			       &peer.s4.sin_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
			       &peer.s4.sin_addr,
			       sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(buffer,
			       &peer.s6.sin6_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
			       &peer.s6.sin6_addr,
			       sizeof(struct in6_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
	     (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
		return 1;

	return 0;
	}



void DTLSProxy::openDTLSsocket(void)
{
	// Open DTLS socket
	memset((void *) &local_addr, 0, sizeof(struct sockaddr_in6));

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0) {
		cout << "Couldn't create DTLS socket\n";
		exit(-1);
	}

	inet_pton(AF_INET6, (const char *)(local_addr_str.c_str()), &local_addr.sin6_addr);
	local_addr.sin6_family = AF_INET6;
	local_addr.sin6_port = htons(dtlsport);
	bind(fd, (const struct sockaddr *) &local_addr, sizeof(struct sockaddr_in6));

	// "Do the DTLS"
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(DTLSv1_server_method());
	/* We accept all ciphers, including NULL.
	 * Not recommended beyond testing and debugging
	 */
	SSL_CTX_set_cipher_list(ctx, "ALL:NULL:eNULL:aNULL");
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

	if (!SSL_CTX_use_certificate_file(ctx, "server-cert.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");

	if (!SSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key (ctx))
		printf("\nERROR: invalid private key!");

	/* Client has to authenticate */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);

	SSL_CTX_set_read_ahead(ctx, 1);
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);



	memset(&remote_addr, 0, sizeof(struct sockaddr_in6));

	/* Create BIO */
	bio = BIO_new_dgram(fd, BIO_NOCLOSE);

	/* Set and activate timeouts */
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

	ssl = SSL_new(ctx);

	SSL_set_bio(ssl, bio, bio);
	SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

//	while (DTLSv1_listen(ssl, &remote_addr) <= 0);
	while (SSL_ctrl(ssl,75,0, (void *)&remote_addr) <= 0);
	cout << "GOT DTLS CONNECT!\n";
}


void DTLSProxy::run(void) {
	int ind=0;
	int len, len_nsp;
	int wr_len, wr_len_nsp;
	struct pollfd pfd;
//	struct sockaddr_in6 raddr;
	int raddr_len;


	pfd.events = (POLLIN | POLLPRI );

	fd_nsp = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd_nsp < 0) {
		cout << "Couldn't create DTLS socket\n";
		exit(-1);
	}
//	inet_pton(AF_INET6, "2001:470:1002:11::54:2009", &local_addr_nsp.sin6_addr);
	inet_pton(AF_INET6, "::1", &local_addr_nsp.sin6_addr);
	local_addr_nsp.sin6_family = AF_INET6;
	local_addr_nsp.sin6_port = htons(3456);

	inet_pton(AF_INET6, nsp_addr_str.c_str(), &nsp_addr.sin6_addr);
	nsp_addr.sin6_family = AF_INET6;
	nsp_addr.sin6_port = htons(5683);

	if(bind(fd_nsp, (const struct sockaddr *) &local_addr_nsp, sizeof(struct sockaddr_in6)) != 0)
	{
		cout << "ERROR - bind() failed for unencrypted socket\n";
		return;
	}
	else
	{
		cout << "bind() succesful for unencrypted socket\n";
	}

	pfd.fd = fd_nsp;

	openDTLSsocket();
	SSL_accept(ssl);

	while (1) {
//		sleep(1);
//		cout << "Checking if data is pending in DTLS socket\n";
//		sleep(2);
		fflush(stdout);

//		if(SSL_pending(ssl) > 0)
		if(1)
		{
//			sleep(2);
			len = SSL_read(ssl, buf, sizeof(buf));
			if(len>0)
			{
				cout << "Received " << len << " bytes from DTLS socket\n";
				cout << "Received " << len << " bytes!\n";
				for(ind=0;ind<len;ind++)
					printf("%2.2x", buf[ind]);

				printf("\n");
//				cout << "Data pending in DTLS socket\n";
			}
			else
			{
				cout << "No data from DTLS socket\n";
			}
//			sleep(2);

			// Write data to normal socket
			sendto(fd_nsp, buf, len, NULL, (const sockaddr *)&nsp_addr, sizeof(nsp_addr));

		}

		{
//			cout << "NO data pending in DTLS socket\n";
//			sleep(2);
			fflush(stdout);

			if(poll(&pfd, 1, 500) > 0)
			{

				if(pfd.revents == POLLIN || pfd.revents == POLLPRI)
				{
					cout << "Incoming data from normal socket\n";

					len_nsp = recvfrom(pfd.fd, buf_nsp, 512, MSG_DONTWAIT, (struct sockaddr *)&nsp_addr, (socklen_t *)&raddr_len);

					cout << "Received " << len_nsp << " bytes from normal (NSP) socket\n";

					// Write data to DTLS socket
					wr_len = SSL_write(ssl, buf_nsp, len_nsp);

					switch (SSL_get_error(ssl, wr_len)) {
					case SSL_ERROR_NONE:
						printf("Wrote %d bytes\n", (int) wr_len);
						break;
					case SSL_ERROR_WANT_WRITE:
						/* Can't write because of a renegotiation, so
						 * we actually have to retry sending this message...
						 */
						printf("ERROR - RENOGIATION IN PROGRESS. NEED TO RESEND!!!\n");
						break;
					case SSL_ERROR_WANT_READ:
						/* continue with reading */
						break;
					case SSL_ERROR_SYSCALL:
						printf("Socket write error: Bailing out... Sorry about that.\n");
						return;
						break;
					case SSL_ERROR_SSL:
						printf("SSL write error\n");
						return;
						break;
					default:
						printf("Unexpected error while writing!\n");
						return;
						break;
					}

				}
			}
			else
			{
				cout << "Normal socket timeout\n";
			}
		}


//
//		cout << "Received " << len << " bytes!\n";
//		for(ind=0;ind<len;ind++)
//			printf("%2.2x", buf[ind]);
//
//		printf("\n");
//
//		while(1)
//			sleep(1);

//		info = (struct pass_info*) malloc (sizeof(struct pass_info));
//		memcpy(&info->server_addr, &server_addr, sizeof(struct sockaddr_storage));
//		memcpy(&info->client_addr, &client_addr, sizeof(struct sockaddr_storage));
//		info->ssl = ssl;


//		if (pthread_create( &tid, NULL, connection_handle, info) != 0) {
//			perror("pthread_create");
//			exit(-1);
//		}
	}





	//
	// Open normal socket
	//
	memset((void *) &local_addr_nsp, 0, sizeof(struct sockaddr_in6));

	fd_nsp = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd_nsp < 0) {
		cout << "Couldn't create local NSP socket\n";
		exit(-1);
	}

	inet_pton(AF_INET6, (const char *)(local_addr_str.c_str()), &local_addr.sin6_addr);
	local_addr.sin6_family = AF_INET6;
	local_addr.sin6_port = htons(0);
	bind(fd, (const struct sockaddr *) &local_addr, sizeof(struct sockaddr_in6));


	while(1)
	{
		sleep(1);
	}

}
