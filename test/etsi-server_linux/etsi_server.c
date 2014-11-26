/**
 * \file 	etsi_server.c
 *
 * \brief	ETSI Plugtest CoAP Server
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
#include <signal.h> /* For SIGIGN and SIGINT */
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include "arguments.h"

/* libCoap includes */
#include "pl_types.h"
#include "sn_nsdl.h"
#include "sn_coap_header.h"
#include "sn_coap_protocol.h"

#define BUFLEN 1024

/* Resource paths and registration parameters */
#define RES_TEST (const char *)("test")
#define RES_SEG (const char *)("seg1/seg2/seg3")
#define RES_QUERY (const char *)("query")
#define RES_SEPARATE (const char *)("separate")
#define RES_LARGE (const char *)("large")
#define RES_LARGE_UPDATE (const char *)("large_update")
#define RES_LARGE_CREATE (const char *)("large_create")
#define RES_OBS (const char *)("obs")
#define RES_WELL_KNOWN (const char *)(".well-known/core")
#define EP (const char *)("etsi-server")
#define EP_LEN 11
#define EP_TYPE (const char *)("")
#define EP_TYPE_LEN 0
#define LINKS (const char *)("</test>,</seg1/seg2/seg3>,</query>,</separate>")
#define LINKS_LEN 46
#define RD_PATH (const char *)("rd")

extern void stop_pgm();

/* Function templates */
void svr_send_msg(sn_coap_hdr_s *coap_hdr_ptr);
int svr_receive_msg(char *buf);
static void svr_msg_handler(char *msg, int len);
void svr_handle_request(sn_coap_hdr_s *coap_packet_ptr);
void svr_handle_request_test(sn_coap_hdr_s *coap_packet_ptr);
void svr_handle_request_seg(sn_coap_hdr_s *coap_packet_ptr);
void svr_handle_request_separate(sn_coap_hdr_s *coap_packet_ptr);
void svr_handle_request_query(sn_coap_hdr_s *coap_packet_ptr);
void svr_handle_request_wellknown(sn_coap_hdr_s *coap_packet_ptr);
int nsp_register(registration_info_t *endpoint_info_ptr);
int nsp_deregister(char *location, uint8_t length);
void *own_alloc(uint16_t size);
void own_free(void* ptr);
uint8_t tx_function(sn_nsdl_capab_e protocol, uint8_t *data_ptr, uint16_t data_len, sn_nsdl_addr_s *address_ptr);
static void ctrl_c_handle_function(void);
typedef void (*signalhandler_t)(int); /* Function pointer type for ctrl-c */

/* Socket globals */
static struct sockaddr_in6 sa_dst, sa_src;
static int sock_server, slen_sa_dst=sizeof(sa_dst);

/* CoAP related globals*/
uint16_t current_mid = 0;
uint8_t	 text_plain = COAP_CT_TEXT_PLAIN;
uint8_t	 link_format = COAP_CT_LINK_FORMAT;

/* Resource related globals*/
char res_test[BUFLEN] = "Sensinode test resource";
char *reg_location;
int8_t reg_location_len;



/*****************************************************/
/* This is called from main to start the CoAP server */
/*****************************************************/
int svr_ipv6(void)
{
	/* Local variables */
	char buf[BUFLEN];
	int rcv_size=0;
	registration_info_t endpoint_info;

	/* Catch ctrl-c */
	if (signal(SIGINT, (signalhandler_t)ctrl_c_handle_function) == SIG_ERR)
	{
		printf("Error with SIGINT: %s\n", strerror(errno));
		return -1;
	}

#ifdef HAVE_DEBUG
	printf("\nCoAP server\nport: %i\n", arg_port);
#endif

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


	/* Initialize the CoAP library */
	sn_coap_builder_and_parser_init(&own_alloc, &own_free);
	sn_coap_protocol_init(&own_alloc, &own_free, &tx_function, NULL);

	/* Initialize random MID */
	srand (time(NULL));
	current_mid = rand() % 10000;

	/* Register with NSP */
#ifdef HAVE_DEBUG
	printf("h: %s\n", EP);
	printf("rt: %s\n", EP_TYPE);
	printf("links: %s\n", LINKS);
#endif
	endpoint_info.endpoint_ptr = (const uint8_t *)EP;
	endpoint_info.endpoint_len = EP_LEN;
	endpoint_info.endpoint_type_ptr = (const uint8_t *)EP_TYPE;
	endpoint_info.endpoint_type_len = EP_TYPE_LEN;
	endpoint_info.links_ptr = (const uint8_t *)LINKS;
	endpoint_info.links_len = LINKS_LEN;

	nsp_register(&endpoint_info);

	/* 				Main loop.				*/
	/* Listen and process incoming messages */
	while (1)
	{
		usleep(100);
		memset(buf, 0, BUFLEN);
		rcv_size = svr_receive_msg(buf);
		svr_msg_handler(buf, rcv_size);
	}
	return 0;
}



/****************************/
/* Message receive function */
/****************************/
int svr_receive_msg(char *buf)
{
  char rcv_in6_addr[32];
  int rcv_size=0;

  memset(rcv_in6_addr,0,32);

  if ((rcv_size=recvfrom(sock_server, buf, BUFLEN, 0, (struct sockaddr *)&sa_dst, (socklen_t*)&slen_sa_dst))==-1)
		stop_pgm("recvfrom()");
  else
  {
	inet_ntop(AF_INET6, &(sa_dst.sin6_addr),rcv_in6_addr,INET6_ADDRSTRLEN);
#ifdef HAVE_DEBUG
	printf("\nRX %s.%d [%d B] - ", rcv_in6_addr, ntohs(sa_dst.sin6_port), rcv_size);
#endif
  }

 return rcv_size;
}


void svr_send_msg(sn_coap_hdr_s *coap_hdr_ptr)
{
	uint8_t 	*message_ptr = NULL;
	uint16_t 	message_len	= 0;
	char dst_in6_addr[32];

	/* Calculate message length */
	message_len = sn_coap_builder_calc_needed_packet_data_size(coap_hdr_ptr);

	/* Allocate memory for message and check was allocating successfully */
	message_ptr = own_alloc(message_len);
	if(!message_ptr)
		return;

	/* Build CoAP message */
	sn_coap_builder(message_ptr, coap_hdr_ptr);

	inet_ntop(AF_INET6, &(sa_dst.sin6_addr),dst_in6_addr,INET6_ADDRSTRLEN);

#ifdef HAVE_DEBUG
	printf("TX %s.%d [%d B] - ", dst_in6_addr, ntohs(sa_dst.sin6_port), message_len);
	sn_coap_packet_debug(coap_hdr_ptr);
#endif

	/* Send the message */
	if (sendto(sock_server, message_ptr, message_len, 0, (const struct sockaddr *)&sa_dst, slen_sa_dst)==-1)
				stop_pgm("sendto() failed");


	own_free(message_ptr);
	own_free(coap_hdr_ptr->payload_ptr);
	if(coap_hdr_ptr->options_list_ptr)
	{
		if(coap_hdr_ptr->options_list_ptr->uri_query_ptr)
			own_free(coap_hdr_ptr->options_list_ptr->uri_query_ptr);
		own_free(coap_hdr_ptr->options_list_ptr);
	}
	own_free(coap_hdr_ptr);
}

int nsp_register(registration_info_t *endpoint_info_ptr)
{
	int rcv_size = 0;
	uint16_t msg_id;
	sn_coap_hdr_s 	*coap_packet_ptr 	= NULL;
	coap_version_e coap_version = COAP_VERSION_1;
	char buf[BUFLEN];

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
	if(!coap_hdr_ptr)
		return -1;
	memset(coap_hdr_ptr, 0x00, sizeof(sn_coap_hdr_s));

	/* Build the registration CoAP request using the libCoap helper function */
	sn_coap_register(coap_hdr_ptr, endpoint_info_ptr);
	msg_id = coap_hdr_ptr->msg_id;
	svr_send_msg(coap_hdr_ptr);

	/* Wait for response */
	usleep(100);
	memset(buf, 0, BUFLEN);
	rcv_size = svr_receive_msg(buf);

	coap_packet_ptr = sn_coap_parser(rcv_size, (uint8_t*)buf, &coap_version);

	/* Check if parsing was successfull */
	if(coap_packet_ptr == (sn_coap_hdr_s *)NULL)
	{
		printf("nsp_register(): CoAP parsing failed\n");
		return -1;
	}

#ifdef HAVE_DEBUG
	sn_coap_packet_debug(coap_packet_ptr);
#endif

	if (coap_packet_ptr->msg_code == COAP_MSG_CODE_RESPONSE_CREATED && coap_packet_ptr->msg_id == msg_id)
	{
		printf("Registration successful.\n");
		/* Save the location handle */
		if (coap_packet_ptr->options_list_ptr && coap_packet_ptr->options_list_ptr->location_path_ptr)
		{
			reg_location_len = coap_packet_ptr->options_list_ptr->location_path_len;
			reg_location = own_alloc(coap_packet_ptr->options_list_ptr->location_path_len);
			if (reg_location)
				memcpy(reg_location, (char *)coap_packet_ptr->options_list_ptr->location_path_ptr, reg_location_len);
			else
			{
				own_free(coap_hdr_ptr);
				return -1;
			}
		}

	}
	else
	{
		return -1;
	}

	sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);

	return 0;
}

int nsp_deregister(char *location, uint8_t length)
{
#ifdef HAVE_DEBUG
	printf("Deregistering from NSP\n");
#endif

	/* Set NSP address and port */
	sa_dst.sin6_family = AF_INET6;
	sa_dst.sin6_port = htons(arg_dport);
	if (inet_pton(AF_INET6, arg_dst, &(sa_dst.sin6_addr))==0)
		stop_pgm("inet_ntop() failed");

	/* Build CoAP request */

	sn_coap_hdr_s *coap_hdr_ptr;
	coap_hdr_ptr = own_alloc(sizeof(sn_coap_hdr_s));
	if(!coap_hdr_ptr)
		return -1;
	memset(coap_hdr_ptr, 0x00, sizeof(sn_coap_hdr_s));

	/* Build the de-registration CoAP request using the libCoap helper function */
	sn_coap_deregister(coap_hdr_ptr, (uint8_t*)location, length);
	svr_send_msg(coap_hdr_ptr);

	return 0;
}

void svr_msg_handler(char *msg, int len)
{

	sn_coap_hdr_s 	*coap_packet_ptr 	= NULL;
	coap_version_e coap_version = COAP_VERSION_1;

	/* Parse the buffer into a CoAP message structure */
	coap_packet_ptr = sn_coap_parser(len, (uint8_t*)msg, &coap_version);

	/* Check if parsing was successfull */
	if(coap_packet_ptr == (sn_coap_hdr_s *)NULL)
	{
		printf("svr_msg_handler(): CoAP parsing failed\n");
		return;
	}

#ifdef HAVE_DEBUG
	sn_coap_packet_debug(coap_packet_ptr);
#endif

	/* If the message code range is a request method, then handle the request */
	if (coap_packet_ptr->msg_code >= 1 && coap_packet_ptr->msg_code <= 4)
	{
		svr_handle_request(coap_packet_ptr);
	}
	
	sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
}


void svr_handle_request(sn_coap_hdr_s *coap_packet_ptr)
{
	/* Compare the request URI against server's resource, pass to resource handler when matching */
	if (memcmp(coap_packet_ptr->uri_path_ptr, RES_TEST, strlen(RES_TEST)) == 0)
		svr_handle_request_test(coap_packet_ptr);
	else if (memcmp(coap_packet_ptr->uri_path_ptr, RES_QUERY, strlen(RES_QUERY)) == 0)
		svr_handle_request_query(coap_packet_ptr);
	else if (memcmp(coap_packet_ptr->uri_path_ptr, RES_SEG, strlen(RES_SEG)) == 0)
		svr_handle_request_seg(coap_packet_ptr);
	else if (memcmp(coap_packet_ptr->uri_path_ptr, RES_SEPARATE, strlen(RES_SEPARATE)) == 0)
		svr_handle_request_separate(coap_packet_ptr);
	else if (memcmp(coap_packet_ptr->uri_path_ptr, RES_WELL_KNOWN, strlen(RES_WELL_KNOWN)) == 0)
		svr_handle_request_wellknown(coap_packet_ptr);		
	/* URI not found */
	else
	{
		printf("URI not found\n");
		sn_coap_hdr_s *coap_res_ptr;
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_NOT_FOUND);
		svr_send_msg(coap_res_ptr);		
	}

}

void svr_handle_request_test(sn_coap_hdr_s *coap_packet_ptr)
{
	sn_coap_hdr_s *coap_res_ptr;
	if (coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
	{
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_CONTENT);
		if (coap_packet_ptr->msg_type == COAP_MSG_TYPE_NON_CONFIRMABLE)
		{
			coap_res_ptr->msg_type = COAP_MSG_TYPE_NON_CONFIRMABLE;
			coap_res_ptr->msg_id = current_mid++;
		}
		coap_res_ptr->content_type_ptr = &text_plain;
		coap_res_ptr->content_type_len = sizeof(text_plain);
		coap_res_ptr->payload_len = strlen(res_test);
		coap_res_ptr->payload_ptr = own_alloc(coap_res_ptr->payload_len);
		if(!coap_res_ptr->payload_ptr)
			return;
		memcpy(coap_res_ptr->payload_ptr, res_test, coap_res_ptr->payload_len);
		svr_send_msg(coap_res_ptr);
		return;
	}
	else if (coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_PUT)
	{
		if (coap_packet_ptr->payload_ptr && coap_packet_ptr->payload_len < sizeof(res_test))
		{
			memset(res_test, 0, sizeof(res_test));
			memcpy(res_test, coap_packet_ptr->payload_ptr, coap_packet_ptr->payload_len);
		}
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_CHANGED);
		if (coap_packet_ptr->msg_type == COAP_MSG_TYPE_NON_CONFIRMABLE)
		{
			coap_res_ptr->msg_type = COAP_MSG_TYPE_NON_CONFIRMABLE;
			coap_res_ptr->msg_id = current_mid++;
		}
		svr_send_msg(coap_res_ptr);
		return;

	} else if (coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_POST)
	{
		if (coap_packet_ptr->payload_ptr && coap_packet_ptr->payload_len < sizeof(res_test))
		{
			memset(res_test, 0, sizeof(res_test));
			memcpy(res_test, coap_packet_ptr->payload_ptr, coap_packet_ptr->payload_len);
		}
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_CREATED);
		if (coap_packet_ptr->msg_type == COAP_MSG_TYPE_NON_CONFIRMABLE)
		{
			coap_res_ptr->msg_type = COAP_MSG_TYPE_NON_CONFIRMABLE;
			coap_res_ptr->msg_id = current_mid++;
		}
		/* Options */
		coap_res_ptr->options_list_ptr = own_alloc(sizeof(sn_coap_options_list_s));
		if(!coap_res_ptr->options_list_ptr )
			return;
		memset(coap_res_ptr->options_list_ptr, 0, sizeof(sn_coap_options_list_s));
		/* Set Location */
		char location[64];
		sprintf(location, "test/new");
		coap_res_ptr->options_list_ptr->location_path_len = strlen(location);
		coap_res_ptr->options_list_ptr->location_path_ptr = own_alloc(coap_res_ptr->options_list_ptr->location_path_len);
		if(!coap_res_ptr->options_list_ptr->location_path_ptr)
		{
			own_free(coap_res_ptr->options_list_ptr);
					return;
		}
		memcpy(coap_res_ptr->options_list_ptr->location_path_ptr, location, coap_res_ptr->options_list_ptr->location_path_len);
		
		svr_send_msg(coap_res_ptr);
		return;

	} else if (coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_DELETE)
	{
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_DELETED);
		if (coap_packet_ptr->msg_type == COAP_MSG_TYPE_NON_CONFIRMABLE)
		{
			coap_res_ptr->msg_type = COAP_MSG_TYPE_NON_CONFIRMABLE;
			coap_res_ptr->msg_id = current_mid++;
		}
		svr_send_msg(coap_res_ptr);
		return;
	}
	/* Method not supported */
	else
	{
		printf("Method not supported\n");
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED);
		svr_send_msg(coap_res_ptr);
	}
}

void svr_handle_request_seg(sn_coap_hdr_s *coap_packet_ptr)
{
	sn_coap_hdr_s *coap_res_ptr;
	if (coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
	{
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_CONTENT);
		coap_res_ptr->content_type_ptr = &text_plain;
		coap_res_ptr->content_type_len = sizeof(text_plain);
		coap_res_ptr->payload_len = strlen(res_test);
		coap_res_ptr->payload_ptr = own_alloc(coap_res_ptr->payload_len);
		if(!coap_res_ptr->payload_ptr)
			return;
		memcpy(coap_res_ptr->payload_ptr, res_test, coap_res_ptr->payload_len);
		svr_send_msg(coap_res_ptr);
		return;
	}
	/* Method not supported */
	else
	{
		printf("Method not supported\n");
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED);
		svr_send_msg(coap_res_ptr);
	}
}

void svr_handle_request_separate(sn_coap_hdr_s *coap_packet_ptr)
{
	sn_coap_hdr_s *coap_res_ptr;
	if (coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
	{

		/* Send an ACK first if it is a CON */
		if (coap_packet_ptr->msg_type == COAP_MSG_TYPE_CONFIRMABLE)
		{
			coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_EMPTY);
			svr_send_msg(coap_res_ptr);
		}

		/* Send NON response */
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_CONTENT);
		coap_res_ptr->msg_type = COAP_MSG_TYPE_NON_CONFIRMABLE;
		coap_res_ptr->msg_id = current_mid++;

		coap_res_ptr->content_type_ptr = &text_plain;
		coap_res_ptr->content_type_len = sizeof(text_plain);
		coap_res_ptr->payload_len = strlen(res_test);
		coap_res_ptr->payload_ptr = own_alloc(coap_res_ptr->payload_len);
		if(!coap_res_ptr->payload_ptr)
			return;
		memcpy(coap_res_ptr->payload_ptr, res_test, coap_res_ptr->payload_len);
		svr_send_msg(coap_res_ptr);
		return;
	}
	/* Method not supported */
	else
	{
		printf("Method not supported\n");
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED);
		svr_send_msg(coap_res_ptr);
	}
}

void svr_handle_request_query(sn_coap_hdr_s *coap_packet_ptr)
{
	sn_coap_hdr_s *coap_res_ptr;
	if (coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
	{
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_CONTENT);
		coap_res_ptr->content_type_ptr = &text_plain;
		coap_res_ptr->content_type_len = sizeof(text_plain);
		/* Return the query string as the payload */
		coap_res_ptr->payload_len = coap_packet_ptr->options_list_ptr->uri_query_len;
		coap_res_ptr->payload_ptr = own_alloc(coap_res_ptr->payload_len);
		if(!coap_res_ptr->payload_ptr)
			return;
		memcpy(coap_res_ptr->payload_ptr, coap_packet_ptr->options_list_ptr->uri_query_ptr, coap_res_ptr->payload_len);
		svr_send_msg(coap_res_ptr);
		return;
	}
	/* Method not supported */
	else
	{
		printf("Method not supported\n");
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED);
		svr_send_msg(coap_res_ptr);
	}
}

void svr_handle_request_wellknown(sn_coap_hdr_s *coap_packet_ptr)
{
	sn_coap_hdr_s *coap_res_ptr;
	if (coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
	{
		printf("GET /.well-known/core\n");
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_CONTENT);
		coap_res_ptr->content_type_ptr = &link_format;
		coap_res_ptr->content_type_len = sizeof(link_format);
		coap_res_ptr->payload_len = strlen(LINKS);
		coap_res_ptr->payload_ptr = own_alloc(coap_res_ptr->payload_len);
		if(!coap_res_ptr->payload_ptr)
			return;
		memcpy(coap_res_ptr->payload_ptr, LINKS, coap_res_ptr->payload_len);
		svr_send_msg(coap_res_ptr);
		return;
	}
	/* Method not supported */
	else
	{
		printf("Method not supported\n");
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED);
		svr_send_msg(coap_res_ptr);
	}
}

/* These alloc and free functions are required for libCoap */
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

/* Unused function needed for libCoap protocol initialization */
uint8_t tx_function(sn_nsdl_capab_e protocol, uint8_t *data_ptr, uint16_t data_len, sn_nsdl_addr_s *address_ptr)
{
	return 0;
}

static void ctrl_c_handle_function(void)
{
	printf("Pressed ctrl-c\n");

	nsp_deregister(reg_location, reg_location_len);
	usleep(100);

	if(reg_location)
		own_free(reg_location);
	sn_coap_protocol_destroy();

	exit(1);
}
