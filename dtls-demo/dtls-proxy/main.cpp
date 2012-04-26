/*
 * main.cpp
 *
 *  Created on: Oct 12, 2011
 *      Author: Mikko
 */

using namespace std;

#include <iostream>
#include <getopt.h>
#include <stdlib.h>
#include "DTLSProxy.hpp"

static struct option long_options[] = {
	{"dtlsport", 1, 0, 0},
	{"plainport", 1, 0, 0},
	{"localaddr", 1, 0, 0},
	{"nspaddr", 1, 0, 0},
	{0, 0, 0, 0}
};

void usage()
{
	cout << "Usage:\n";
	cout << "./DTLS-Proxy [OPTIONS]\n";
	cout << "-d/--dtlsport [DTLS secure portnumber(towards endpoint)]\n";
	cout << "-p/--plainport [Unsecured portnumber (towards NSP)]\n";
	cout << "-l/--dtlsaddr [Local interface IPv6 address for DTLS server]\n";
	cout << "-n/--nspaddr [Address of the NSP]\n";
	cout << "-h/--help\n";
}


int main(int argc, char **argv)
{
	DTLSProxy *proxy;
	int c;
	int opt_ind = 0;
	int dtlsport;
	int port;
	string local_addr;
	string nsp_addr;

	cout << "This is DTLS Proxy 0.1\n";

	while(1)
	{
		c = getopt_long (argc, argv, "d:p:l:n:h", long_options, &opt_ind);
		if (c == -1)
		{
			cout << "Parsed through all arguments\n";

			break;
		}

		switch(c)
		{
		case 'd':
			dtlsport = (int)atoi(optarg);
			cout << "DTLS secured portnumber: " << dtlsport << "\n";
			break;
		case 'p':
			port = (int)atoi(optarg);
			cout << "Unsecure portnumber: " << port << "\n";
			break;
		case 'l':
			local_addr = optarg;
			cout << "Local interface address:" << local_addr << "\n";
			break;
		case 'n':
			nsp_addr = optarg;
			cout << "NSP address:" << nsp_addr << "\n";
			break;
		case 'h':
			usage();
			return(1);
		default:
			cout << "Unknown argument\n";
			break;
		}

	}


	proxy = new DTLSProxy(dtlsport, port, local_addr, nsp_addr);

	proxy->run();

	return(1);
}



