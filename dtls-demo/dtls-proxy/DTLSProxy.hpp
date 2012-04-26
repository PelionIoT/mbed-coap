/*
 * DTLSProxy.hpp
 *
 *  Created on: Oct 12, 2011
 *      Author: Mikko
 */

#ifndef DTLSPROXY_HPP_
#define DTLSPROXY_HPP_

#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

namespace std {

class DTLSProxy {
public:
	DTLSProxy(int dtlsport, int port, string local_addr, string nsp_addr);
	virtual ~DTLSProxy();

	void run(void);
	void openDTLSsocket(void);

	int dtlsport;
	int port;

	string local_addr_str;
	string nsp_addr_str;
	struct sockaddr_in6 local_addr;
	int fd;
	struct sockaddr_in6 local_addr_nsp;
	int fd_nsp;

	struct sockaddr_in6 remote_addr;
	struct sockaddr_in6 nsp_addr;

	struct timeval timeout;

	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;

	unsigned char buf[512];
	unsigned char buf_nsp[512];
};

} /* namespace std */
#endif /* DTLSPROXY_HPP_ */
