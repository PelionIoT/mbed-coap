/**
 * \file 	main.c
 *
 * \brief	Command line parameter parsing for Connected Home server
 *
 * \author 	Zach Shelby <zach@sensinode.com>
 *
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "arguments.h"

extern int svr_ipv6();

void stop_pgm(char *s)
{
	perror(s);
	exit(1);
}

void arg_init(void)
{
	memcpy(arg_dst,"::1",32); 	//default localhost
	arg_port=8000; 					
	arg_sport=5683;
	arg_dport=5683;
}

void usage_show(void)
{
	printf("Usage:\n\n"

			"connected-home [-p 8000] \n"
			"-p	port to listen on (default = 8000)\n"
			"-d	NSP IPv6 address (default = ::1)\n"
			"-dp NSP port number (default = 5683)\n");
}

int main(int argc, char **argv)
{
	uint8_t i;
	arg_init();

	if (argc<1)
	{
		usage_show();
	}
	else
	{
		i=1; //argv[0] is the command itself
		
		argc--; //get the real number of arguments
		while (i<=argc)
		{
			//check arguments
			if (!(strcmp("-h",argv[i])))
			{
				usage_show();
				stop_pgm("");
			}
			else if (!(strcmp("-d",argv[i])))
			{
				if (i++==argc) stop_pgm("Argument missed for option -d\n");
				memcpy(arg_dst,argv[i],strlen((const char*)argv[i])+1);
				i++;
				continue;
			}
			else if (!(strcmp("-p",argv[i])))
			{
				if (i++==argc) stop_pgm("Argument missed for option -p\n");
				arg_port=atoi(argv[i]);
				i++;
				continue;
			}
			else if (!(strcmp("-dp",argv[i])))
			{
				if (i++==argc) stop_pgm("Argument missed for option -dp\n");
				arg_dport=atoi(argv[i]);
				i++;
				continue;
			}
			else if (!(strcmp("-sp",argv[i])))
			{
				if (i++==argc) stop_pgm("Argument missed for option -sp\n");
				arg_sport=atoi(argv[i]);
				i++;
				continue;
			}
			else
			{
				usage_show();
				stop_pgm("\n--- Argument error ---\n");
			}

		}

		/* Start the CoAP server */
		svr_ipv6();

	}
	return 0;
}


