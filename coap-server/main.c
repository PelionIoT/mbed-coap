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
//extern int client_ipv6();

void stop_pgm(char *s)
{
	perror(s);
	exit(1);
}

//initialize arguments
void arg_init(void)
{
	arg_mode = NONE;
	memcpy(arg_dst,"::1",32); 		//default loopback address
	arg_port=8000; 					
	arg_sport=5683;
	arg_dport=5683;
	arg_dtlsport=8001;
	arg_tid = 0;
	arg_hdr_type = 0; /*CONFIRM*/
	arg_dtls = FALSE;
	arg_gui = FALSE;
	arg_uri_path=NULL;
	arg_payload = NULL;
	st = NULL;
	arg_code=0;						        //default code of 0
	arg_method=1;							//default Method = GET
	arg_content_type=0; 					//default = TEXT_PLAIN
	option_count = 0;
}

void usage_show(void)
{
	printf("Usage:\n\n"

			"help\ncoap_server -h\n\n"

			"server mode\ncoap [-p 8000] \n"
			"-p	port to listen on (default = 8000)\n"
			"-d	NSP IPv6 address (default = ::1)\n"
			"-dp NSP port number (default = 5863)\n"
			"-dtls dtls proxy port(flag to run in DTLS mode)\n"
			"-gui (flag to use GUI applet)\n");			
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
			else if (!(strcmp("-c",argv[i])))
			{
				if (arg_mode == NONE) {
					arg_mode=CLIENT;
				} else {
					usage_show();
					stop_pgm("\n--- Argument error: use -c or -s not both ---\n");
				}
				i++;
				continue;
			}
			else if (!(strcmp("-s",argv[i])))
			{
				if (arg_mode == NONE) {
					arg_mode=SERVER;
				} else {
					usage_show();
					stop_pgm("\n--- Argument error: use -c or -s not both ---\n");
				}
				i++;
				continue;
			}
			else if (!(strcmp("-dtls",argv[i])))
			{
				arg_dtls = TRUE;
				if (i++!=argc)
					arg_dtlsport=atoi(argv[i]);
				i++;
				continue;
			}
			else if (!(strcmp("-gui",argv[i])))
			{
				arg_gui = TRUE;
				i++;
				continue;
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
/*			else if (!(strcmp("-e",argv[i])))
			{
				if (i++==argc) stop_pgm("Argument missed for option -e\n");
				arg_content=(unsigned char*) argv[i];
				i++;
				continue;
			}*/
			else if (!(strcmp("-m",argv[i])))
			{
				int l=0;
				if (i++==argc) stop_pgm("Argument missed for option -m\n");
				l=strlen((const char*)argv[i]);
				st=(unsigned char*) argv[i];
				//printf("\nstring = %s, length = %d, i = %d\n", st,l, i);
				if (strcmp("GET", (const char *)st)==0) {arg_method=1;}
 				else if (strcmp("POST",(const char *)st) ==0) {arg_method=2;}
				else if (strcmp("PUT",(const char *)st) ==0) {arg_method=3;}
				else if (strcmp("DELETE",(const char *)st) ==0) {arg_method=4;}
	   			else {stop_pgm("Invalid method");}
//				printf("arg_method = %d\n",arg_method);
				i++;
				continue;
			}
			else if (!(strcmp("-ht",argv[i])))
			{
				if (i++==argc) stop_pgm("Argument missed for option -ht\n");
				arg_hdr_type=atoi(argv[i]);
				if (arg_hdr_type > 3) stop_pgm("Invalid Header Type.");
				i++;
				continue;
			}
			else if (!(strcmp("-ot",argv[i])))
			{
				if (i++==argc) stop_pgm("Argument missed for option -ot\n");
				arg_content_type=atoi(argv[i]);
				option_type[option_count] = 0; /*CONTENT_TYPE*/
				option_count++;
				i++;
				continue;
			}
			else if (!(strcmp("-tid",argv[i])))
			{
				if (i++==argc) stop_pgm("Argument missed for option -tid\n");
				arg_tid=atoi(argv[i]);
				//printf("COAP_Test tid = %d\n", arg_tid);
				i++;
				continue;
			}
			else if (!(strcmp("-ou",argv[i])))
			{
				uint8_t len=0;
				if (i++==argc) stop_pgm("Argument missed for option -ou\n");
				len=strlen((const char*)argv[i]);
				arg_uri_path=(unsigned char*) argv[i];
				i=i+len;
				option_type[option_count] = 9; /*URI_PATH*/
				option_count++;
				//printf("COAP_test: option_count=%d\n", option_count);
				continue;

			}
		/*	else if (!(strcmp("-up",argv[i])))
			{
				uint8_t len1=0;
				if (i++==argc) stop_pgm("Argument missed for option -up\n");
				len1=strlen((const char*)argv[i]);
				arg_payload=(unsigned char*) argv[i];
				i=i+len1;
				continue;
			}*/
			else
			{
				usage_show();
				stop_pgm("\n--- Argument error ---\n");
			}

		}

		/* Run the CoAP server */
		svr_ipv6();

	}
	return 0;
}


