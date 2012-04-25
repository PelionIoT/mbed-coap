/**
 * \file
 *			Constained application protocol (CoAP)
 * \authors
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
#include <fcntl.h>
#include <time.h>
#include "arguments.h"

#ifdef HAVE_DTLS
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif

#include "pl_types.h"
#include "sn_linked_list.h"
#include "sn_nsdl.h"
#include "sn_coap_header.h"
#include "sn_coap_protocol.h"

#define BUFLEN 1024

#define RES_AUTO_LIGHTS (const char *)("auto/lights")
#define RES_GPS_LOC (const char *)("gps/loc")
#define EP (const char *)("car-dtls")
#define EP_TYPE (const char *)("car")
#define LINKS (const char *)("</auto/lights>;rt=\"ns:auto-lights\",</gps/loc>;rt=\"ns:gpsloc\"")
#define RD_PATH (const char *)("rd")
#define RES_WELL_KNOWN (const char *)(".well-known/core")

extern void stop_pgm();

/* Function templates */
void svr_send_msg(sn_coap_hdr_s *coap_hdr_ptr);
static void svr_msg_handler(char *msg, int len);
void svr_handle_request(sn_coap_hdr_s *coap_packet_ptr);
int nsp_register(const char *ep, const char *rt, const char *links);
void coap_packet_debug(sn_coap_hdr_s *coap_packet_ptr);
void *own_alloc(uint16_t size);
void own_free(void* ptr);

/* Socket globals */
static struct sockaddr_in6 sa_dst, sa_src, sa_light_src, sa_light_dst;
static int sock_server, sock_light, slen_sa_dst=sizeof(sa_dst);

#ifdef HAVE_DTLS
extern SSL *ssl;
extern void dtls_start(char *remote_address, char *local_address, int port, int length, int messagenumber);
#endif


/* CoAP related globals*/
uint16_t	current_mid = 0;
uint8_t		link_format = 40;

/* Resource related globals*/
char	res_auto_light = '0';
char	light_on = '1';
char	light_off = '0';
const char  res_gps_loc[] = "65.000035,25.460185";

int svr_ipv6(void)
{
	char buf[BUFLEN], rcv_in6_addr[32];
	int rcv_size=0;

	printf("\nCoAP server\nport: %i\n", arg_port);

if (arg_dtls == FALSE)
{
	/* Open the server socket*/
	if ((sock_server=socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP))==-1)
		stop_pgm("socket() error");

	/* Init the listen port addr*/
	memset((char *) &sa_src, 0, sizeof(sa_src));
	sa_src.sin6_family = AF_INET6;
	sa_src.sin6_port = htons(arg_port);

	/* Listen to the port */
	if (inet_pton(AF_INET6, "::", &sa_src.sin6_addr)==0)
		stop_pgm("inet_ntop() failed");
	if (bind(sock_server, (struct sockaddr *) &sa_src, sizeof(sa_src))==-1)
		stop_pgm("bind() error");
} 
#ifdef HAVE_DTLS
else if (arg_dtls == TRUE)
{
	dtls_start("::1", 0, arg_dtlsport, 15, 12);
}
#endif

	/* Open the light applet socket */
	
	/*Open the socket*/
	if ((sock_light=socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP))==-1)
		stop_pgm("socket() error");

	/* Init the src port addr*/
	memset((char *) &sa_light_src, 0, sizeof(sa_light_src));
	sa_light_src.sin6_family = AF_INET6;
	sa_light_src.sin6_port = htons(60105);

	/* Listen to the port */
	if (inet_pton(AF_INET6, "::", &sa_light_src.sin6_addr)==0)
		stop_pgm("inet_ntop() failed");
	if (bind(sock_light, (struct sockaddr *) &sa_light_src, sizeof(sa_light_src))==-1)
		stop_pgm("bind() error");

	/* Init destination addr*/
	memset((char *) &sa_light_dst, 0, sizeof(sa_light_dst));
	sa_light_dst.sin6_family = AF_INET6;
	sa_light_dst.sin6_port = htons(60106);
	if (inet_pton(AF_INET6, "::1", &sa_light_dst.sin6_addr)==0)
		stop_pgm("inet_pton() failed\n");


	/* Initialize the CoAP library */
	sn_coap_builder_and_parser_init(&own_alloc, &own_free);
	srand (time(NULL));
	current_mid = rand() % 10000;

	/* Register with NSP */
	printf("h: %s\n", EP);
	printf("rt: %s\n", EP_TYPE);
	printf("links: %s\n", LINKS);
	nsp_register(EP, EP_TYPE, LINKS);

	/*listen and process incoming message*/
	while (1)
	{
		usleep(500);
		memset(rcv_in6_addr,0,32);
		
	  if (arg_dtls == FALSE) 
	  {
		if ((rcv_size=recvfrom(sock_server, buf, BUFLEN, 0, (struct sockaddr *)&sa_dst, (socklen_t*)&slen_sa_dst))==-1)
			stop_pgm("recvfrom()");
		else
		{
			inet_ntop(AF_INET6, &(sa_dst.sin6_addr),rcv_in6_addr,INET6_ADDRSTRLEN);
#ifdef HAVE_DEBUG
			printf("RX %s.%d [%d B] - ", rcv_in6_addr, ntohs(sa_dst.sin6_port), rcv_size);
#endif
			svr_msg_handler(buf, rcv_size);
		}
	  } 
#ifdef HAVE_DTLS
  	  else if (arg_dtls == TRUE)
      {
  	     	rcv_size = SSL_read(ssl, buf, BUFLEN);
  	     	if (rcv_size > 0)
  	     	{
#ifdef HAVE_DEBUG
				printf("RX dtls [%d B] - ", rcv_size);
#endif
				svr_msg_handler(buf, rcv_size);  	  
			}   	
      }
#endif
	}

	return 0;
}

void svr_send_msg(sn_coap_hdr_s *coap_hdr_ptr)
{
	uint8_t 	*message_ptr = NULL;
	uint16_t 	message_len	= 0;
	int 	sent = 0;
	char dst_in6_addr[32];

	/* Build CoAP message */

	/* Calculate message length */
	message_len = sn_coap_builder_calc_needed_packet_data_size(coap_hdr_ptr);

	/* Allocate memory for message and check was allocating successfully */
	message_ptr = own_alloc(message_len);

	/* Build CoAP message */
	sn_coap_builder(message_ptr, coap_hdr_ptr);

	inet_ntop(AF_INET6, &(sa_dst.sin6_addr),dst_in6_addr,INET6_ADDRSTRLEN);
#ifdef HAVE_DEBUG
  if (arg_dtls == FALSE)
	printf("TX %s.%d [%d B] - ", dst_in6_addr, ntohs(sa_dst.sin6_port), message_len);
  else if (arg_dtls == TRUE)
  	printf("TX dtls [%d B] - ", message_len);
  coap_packet_debug(coap_hdr_ptr);
#endif

	/* Send the message */
  if (arg_dtls == FALSE) 
  {
	if (sendto(sock_server, message_ptr, message_len, 0, (const struct sockaddr *)&sa_dst, slen_sa_dst)==-1)
				stop_pgm("sendto() failed");
  } 
#ifdef HAVE_DTLS
  else if (arg_dtls == TRUE)
  {
  	sent = SSL_write(ssl, message_ptr, message_len);
  	if (sent <= 0)
  		stop_pgm("SSL_write failed");
  }
#endif

  own_free(message_ptr);
  own_free(coap_hdr_ptr->payload_ptr);
  own_free(coap_hdr_ptr->options_list_ptr);
  own_free(coap_hdr_ptr);

}

int nsp_register(const char *ep, const char *rt, const char *links)
{

#ifdef HAVE_DEBUG
	printf("Registering with NSP\n");
#endif

	/* Set NSP address and port */
	sa_dst.sin6_family = AF_INET6;
	sa_dst.sin6_port = htons(arg_dport);	
	if (inet_pton(AF_INET6, arg_dst, &(sa_dst.sin6_addr))==0)
		stop_pgm("inet_ntop() failed");

	/* Build CoAP request */

	sn_coap_hdr_s *coap_hdr_ptr;
	coap_hdr_ptr = own_alloc(sizeof(sn_coap_hdr_s));
	memset(coap_hdr_ptr, 0x00, sizeof(sn_coap_hdr_s));
	coap_hdr_ptr->msg_code = COAP_MSG_CODE_REQUEST_POST;
	coap_hdr_ptr->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
	coap_hdr_ptr->msg_id = current_mid;
	coap_hdr_ptr->uri_path_len = strlen(RD_PATH);
	coap_hdr_ptr->uri_path_ptr = (uint8_t*)RD_PATH;
	coap_hdr_ptr->payload_len = strlen(links);
	coap_hdr_ptr->payload_ptr = own_alloc(coap_hdr_ptr->payload_len);
	memcpy(coap_hdr_ptr->payload_ptr, links, coap_hdr_ptr->payload_len);
	/* Options */
	coap_hdr_ptr->options_list_ptr = own_alloc(sizeof(sn_coap_options_list_s));
	memset(coap_hdr_ptr->options_list_ptr, 0, sizeof(sn_coap_options_list_s));
	
	char query[64];
	sprintf(query, "h=%s&rt=%s", EP, EP_TYPE);
	coap_hdr_ptr->options_list_ptr->uri_query_len = strlen(query);
	coap_hdr_ptr->options_list_ptr->uri_query_ptr = own_alloc(coap_hdr_ptr->options_list_ptr->uri_query_len);
	memcpy(coap_hdr_ptr->options_list_ptr->uri_query_ptr, query, coap_hdr_ptr->options_list_ptr->uri_query_len);

	svr_send_msg(coap_hdr_ptr);
	current_mid++;

	return 0;
}

void svr_msg_handler(char *msg, int len)
{

	sn_coap_hdr_s 	*coap_packet_ptr 	= NULL;
	coap_version_e coap_version = COAP_VERSION_1;

	//printf("svr_msg_handler()\n");

	coap_packet_ptr = sn_coap_parser(len, (uint8_t*)msg, &coap_version);

	/* Check if parsing was successfull */
	if(coap_packet_ptr == (sn_coap_hdr_s *)NULL)
	{
		printf("svr_msg_handler(): CoAP parsing failed\n");
		return;
	}
	

#ifdef HAVE_DEBUG
	coap_packet_debug(coap_packet_ptr);
#endif

	if (coap_packet_ptr->msg_code >= 1 && coap_packet_ptr->msg_code <= 4)
	{
		svr_handle_request(coap_packet_ptr);
	}
	
	sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
}


void svr_handle_request(sn_coap_hdr_s *coap_packet_ptr)
{
	uint8_t 	*message_ptr = NULL;
	uint16_t 	message_len	= 0;

	//printf("svr_handle_request()\n");
	/* /auto/lights */
	if (memcmp(coap_packet_ptr->uri_path_ptr, RES_AUTO_LIGHTS, strlen(RES_AUTO_LIGHTS)) == 0)
	{
		if (coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
		{
			printf("GET Auto Lights\n");
			
			sn_coap_hdr_s *coap_res_ptr;
			coap_res_ptr = own_alloc(sizeof(sn_coap_hdr_s));
			memset(coap_res_ptr, 0x00, sizeof(sn_coap_hdr_s));
			coap_res_ptr->msg_code = COAP_MSG_CODE_RESPONSE_CONTENT;
			coap_res_ptr->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
			coap_res_ptr->msg_id = coap_packet_ptr->msg_id;
			coap_res_ptr->payload_len = 1;
			coap_res_ptr->payload_ptr = own_alloc(coap_res_ptr->payload_len);
			memcpy(coap_res_ptr->payload_ptr, &res_auto_light, coap_res_ptr->payload_len);
			svr_send_msg(coap_res_ptr);
			return;
		}
		else if (coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_PUT)
		{
		  if (coap_packet_ptr->payload_ptr)
		  { 
			if (memcmp(coap_packet_ptr->payload_ptr, &light_on, coap_packet_ptr->payload_len) == 0)
			{
				printf("Turn Auto Lights ON\n");
				res_auto_light = light_on;
				sn_coap_hdr_s *coap_res_ptr;
				coap_res_ptr = own_alloc(sizeof(sn_coap_hdr_s));
				memset(coap_res_ptr, 0x00, sizeof(sn_coap_hdr_s));
				coap_res_ptr->msg_code = COAP_MSG_CODE_RESPONSE_CHANGED;
				coap_res_ptr->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
				coap_res_ptr->msg_id = coap_packet_ptr->msg_id;
				svr_send_msg(coap_res_ptr);

				/* Send the light applet message */
				message_len = 1;
				message_ptr = own_alloc(message_len);
				message_ptr[0] = res_auto_light;
				if (sendto(sock_light, message_ptr, message_len, 0, (const struct sockaddr *)&sa_light_dst, slen_sa_dst)==-1)
					stop_pgm("sendto() failed");
				return;
					
			} else if (memcmp(coap_packet_ptr->payload_ptr, &light_off, coap_packet_ptr->payload_len) == 0) { 
				printf("Turn Auto Lights OFF\n");
				res_auto_light = light_off;
				sn_coap_hdr_s *coap_res_ptr;
				coap_res_ptr = own_alloc(sizeof(sn_coap_hdr_s));
				memset(coap_res_ptr, 0x00, sizeof(sn_coap_hdr_s));
				coap_res_ptr->msg_code = COAP_MSG_CODE_RESPONSE_CHANGED;
				coap_res_ptr->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
				coap_res_ptr->msg_id = coap_packet_ptr->msg_id;
				svr_send_msg(coap_res_ptr);
				
				/* Send the light applet message */
				message_len = 1;
				message_ptr = own_alloc(message_len);
				message_ptr[0] = res_auto_light;
				if (sendto(sock_light, message_ptr, message_len, 0, (const struct sockaddr *)&sa_light_dst, slen_sa_dst)==-1)
					stop_pgm("sendto() failed");
				return;
			}
		  }
		} else { /* Method not supported */
			printf("Method not supported\n");
			sn_coap_hdr_s *coap_res_ptr;
			coap_res_ptr = own_alloc(sizeof(sn_coap_hdr_s));
			memset(coap_res_ptr, 0x00, sizeof(sn_coap_hdr_s));
			coap_res_ptr->msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
			coap_res_ptr->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
			coap_res_ptr->msg_id = coap_packet_ptr->msg_id;
			svr_send_msg(coap_res_ptr);
		}
	/* /gps/loc resource */
	} else if (memcmp(coap_packet_ptr->uri_path_ptr, RES_GPS_LOC, strlen(RES_GPS_LOC)) == 0)
	{
		if (coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
		{
			printf("GET GPS Location\n");
			
			sn_coap_hdr_s *coap_res_ptr;
			coap_res_ptr = own_alloc(sizeof(sn_coap_hdr_s));
			memset(coap_res_ptr, 0x00, sizeof(sn_coap_hdr_s));
			coap_res_ptr->msg_code = COAP_MSG_CODE_RESPONSE_CONTENT;
			coap_res_ptr->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
			coap_res_ptr->msg_id = coap_packet_ptr->msg_id;
			coap_res_ptr->payload_len = strlen(res_gps_loc);
			coap_res_ptr->payload_ptr = own_alloc(coap_res_ptr->payload_len);
			memcpy(coap_res_ptr->payload_ptr, &res_gps_loc, coap_res_ptr->payload_len);
			svr_send_msg(coap_res_ptr);
			return;
		} else { /* Method not supported */
			printf("Method not supported\n");
			sn_coap_hdr_s *coap_res_ptr;
			coap_res_ptr = own_alloc(sizeof(sn_coap_hdr_s));
			memset(coap_res_ptr, 0x00, sizeof(sn_coap_hdr_s));
			coap_res_ptr->msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
			coap_res_ptr->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
			coap_res_ptr->msg_id = coap_packet_ptr->msg_id;
			svr_send_msg(coap_res_ptr);
		}	
		/* /.well-known/core resource */
		} else if (memcmp(coap_packet_ptr->uri_path_ptr, RES_WELL_KNOWN, strlen(RES_WELL_KNOWN)) == 0)
		{
			if (coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
			{
				printf("GET /.well-known/core\n");

				sn_coap_hdr_s *coap_res_ptr;
				coap_res_ptr = own_alloc(sizeof(sn_coap_hdr_s));
				memset(coap_res_ptr, 0x00, sizeof(sn_coap_hdr_s));
				coap_res_ptr->msg_code = COAP_MSG_CODE_RESPONSE_CONTENT;
				coap_res_ptr->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
				coap_res_ptr->msg_id = coap_packet_ptr->msg_id;
				coap_res_ptr->content_type_ptr = &link_format;
				coap_res_ptr->content_type_len = sizeof(link_format);
				coap_res_ptr->payload_len = strlen(LINKS);
				coap_res_ptr->payload_ptr = own_alloc(coap_res_ptr->payload_len);
				memcpy(coap_res_ptr->payload_ptr, LINKS, coap_res_ptr->payload_len);
				svr_send_msg(coap_res_ptr);
				return;
			} else { /* Method not supported */
				printf("Method not supported\n");
				sn_coap_hdr_s *coap_res_ptr;
				coap_res_ptr = own_alloc(sizeof(sn_coap_hdr_s));
				memset(coap_res_ptr, 0x00, sizeof(sn_coap_hdr_s));
				coap_res_ptr->msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
				coap_res_ptr->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
				coap_res_ptr->msg_id = coap_packet_ptr->msg_id;
				svr_send_msg(coap_res_ptr);
			}
	} else { /* URI not found */
		printf("URI not found\n");
		sn_coap_hdr_s *coap_res_ptr;
		coap_res_ptr = own_alloc(sizeof(sn_coap_hdr_s));
		memset(coap_res_ptr, 0x00, sizeof(sn_coap_hdr_s));
		coap_res_ptr->msg_code = COAP_MSG_CODE_RESPONSE_NOT_FOUND;
		coap_res_ptr->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
		coap_res_ptr->msg_id = coap_packet_ptr->msg_id;
		svr_send_msg(coap_res_ptr);		
	}

}

void coap_packet_debug(sn_coap_hdr_s *coap_packet_ptr) 
{

	//printf("\ncoap_packet_debug(): msg_type ");
	switch (coap_packet_ptr->msg_type)
	{
		case COAP_MSG_TYPE_CONFIRMABLE:
            printf("con ");
            break;

		case COAP_MSG_TYPE_NON_CONFIRMABLE:
            printf("non ");
            break;
            
		case COAP_MSG_TYPE_ACKNOWLEDGEMENT:
            printf("ack ");
            break;

		case COAP_MSG_TYPE_RESET:
            printf("rst ");
            break;
	}

	//printf("\ncoap_packet_debug(): msg_code ");
	switch (coap_packet_ptr->msg_code)
	{
        case COAP_MSG_CODE_EMPTY:
            printf("NO CODE ");
            break;

        case COAP_MSG_CODE_REQUEST_GET:
            printf("GET ");
            break;

        case COAP_MSG_CODE_REQUEST_POST:
            printf("POST ");
            break;

        case COAP_MSG_CODE_REQUEST_PUT:
            printf("PUT ");
            break;

        case COAP_MSG_CODE_REQUEST_DELETE:
            printf("DELETE ");
            break;

        case COAP_MSG_CODE_RESPONSE_CREATED:
            printf("2.01 Created ");
            break;

        case COAP_MSG_CODE_RESPONSE_DELETED:
            printf("2.02 Deleted ");
            break;

        case COAP_MSG_CODE_RESPONSE_VALID:
            printf("2.03 Valid ");
            break;

        case COAP_MSG_CODE_RESPONSE_CHANGED:
            printf("2.04 Changed ");
            break;

        case COAP_MSG_CODE_RESPONSE_CONTENT:
            printf("2.05 Content ");
            break;

        case COAP_MSG_CODE_RESPONSE_BAD_REQUEST:
            printf("COAP_MSG_CODE_RESPONSE_BAD_REQUEST\n");
            break;

        case COAP_MSG_CODE_RESPONSE_UNAUTHORIZED:
            printf("COAP_MSG_CODE_RESPONSE_UNAUTHORIZED\n");
            break;

        case COAP_MSG_CODE_RESPONSE_BAD_OPTION:
            printf("COAP_MSG_CODE_RESPONSE_BAD_OPTION\n");
            break;

        case COAP_MSG_CODE_RESPONSE_FORBIDDEN:
            printf("COAP_MSG_CODE_RESPONSE_FORBIDDEN\n");
            break;

        case COAP_MSG_CODE_RESPONSE_NOT_FOUND:
            printf("4.04 Not Found ");
            break;

        case COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED:
            printf("4.05 Method Not Allowed ");
            break;

        case COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_INCOMPLETE:
            printf("COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_INCOMPLETE\n");
            break;

        case COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_TOO_LARGE:
            printf("COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_TOO_LARGE\n");
            break;

        case COAP_MSG_CODE_RESPONSE_UNSUPPORTED_MEDIA_TYPE:
            printf("COAP_MSG_CODE_RESPONSE_UNSUPPORTED_MEDIA_TYPE\n");
            break;

        case COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR:
            printf("COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR\n");
            break;

        case COAP_MSG_CODE_RESPONSE_NOT_IMPLEMENTED:
            printf("COAP_MSG_CODE_RESPONSE_NOT_IMPLEMENTED\n");
            break;

        case COAP_MSG_CODE_RESPONSE_BAD_GATEWAY:
            printf("COAP_MSG_CODE_RESPONSE_BAD_GATEWAY\n");
            break;

        case COAP_MSG_CODE_RESPONSE_SERVICE_UNAVAILABLE:
            printf("COAP_MSG_CODE_RESPONSE_SERVICE_UNAVAILABLE ");
            break;

        case COAP_MSG_CODE_RESPONSE_GATEWAY_TIMEOUT:
            printf("COAP_MSG_CODE_RESPONSE_GATEWAY_TIMEOUT ");
            break;

        case COAP_MSG_CODE_RESPONSE_PROXYING_NOT_SUPPORTED:
            printf("COAP_MSG_CODE_RESPONSE_PROXYING_NOT_SUPPORTED ");
            break;

            printf("UNKNOWN CODE ");
            break;
    }

	//printf("\ncoap_packet_debug(): msg_id ");
    printf("mid=%i ", (int)(coap_packet_ptr->msg_id));

	//printf("\ncoap_packet_debug(): uri_path ");
	if (coap_packet_ptr->uri_path_ptr)
	{
		int i;
		printf("/");
		for (i=0; i < coap_packet_ptr->uri_path_len; i++) printf("%c", (char)(coap_packet_ptr->uri_path_ptr[i]));
		if (coap_packet_ptr->options_list_ptr && coap_packet_ptr->options_list_ptr->uri_query_ptr)
		{
			printf("?");
			for (i=0; i < coap_packet_ptr->options_list_ptr->uri_query_len; i++) printf("%c", (char)(coap_packet_ptr->options_list_ptr->uri_query_ptr[i]));
		}
		printf(" ");
    }
     
    //printf("\ncoap_packet_debug(): token ");
	if (coap_packet_ptr->token_ptr)
	{
		int i;
		printf("token=");
		for (i=0; i < coap_packet_ptr->token_len; i++) printf("%c", (char)(coap_packet_ptr->token_ptr[i]));
		printf(" ");
	}    
    
    //printf("\ncoap_packet_debug(): content-type ");
    if (coap_packet_ptr->content_type_ptr)
    {
    	printf("ct=%i ", (int)(coap_packet_ptr->content_type_ptr[0]));
    }
    
    //printf("\ncoap_packet_debug(): payload ");
    if (coap_packet_ptr->payload_ptr)
    {
		int i;
		printf("'");
		for (i=0; i < coap_packet_ptr->payload_len; i++) printf("%c", (char)(coap_packet_ptr->payload_ptr[i]));
		printf("' ");
    } 
    
	printf("\n");
}

void *own_alloc(uint16_t size)
{
	if(size)
		return malloc(size);
	else
		return 0;
}

void own_free(void *ptr)
{
	if(ptr)
		free(ptr);
}
