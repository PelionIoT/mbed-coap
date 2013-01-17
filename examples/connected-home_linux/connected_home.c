/**
 * \file 	connected-home.c
 *
 * \brief	Connected Home CoAP Server. Emulates a power node.
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

#ifdef USE_EDTLS
#include "shalib.h"
#include "sn_edtls_lib.h"
#include "TI_aes.h"
#endif

#define BUFLEN 1024
#define MAX_CONNECTING_TIME 200

/* Resource paths and registration parameters */
#define RES_MFG	(const char *)("dev/mfg")
#define RES_MFG_VAL	(const char *)("Sensinode")
#define RES_MDL	(const char *)("dev/mdl")
#define RES_MDL_VAL	(const char *)("NSDL-C power node")
#define RES_BAT	(const char *)("dev/bat")
#define RES_BAT_VAL	(const char *)("3.31")
#define RES_PWR (const char *)("pwr/0/w")
#define RES_PWR_VAL	(const char *)("80")
#define RES_PWR_VAL_OFF	(const char *)("0")
#define RES_REL (const char *)("pwr/0/rel")
#define RES_TEMP (const char *)("sen/temp")
#define RES_TEMP_VAL (const char *)("25.4")

#define RES_WELL_KNOWN (const char *)(".well-known/core")
#define EP (const char *)("nsdlc-power")
#define EP_LEN 11
#define EP_TYPE (const char *)("PowerNode")
#define EP_TYPE_LEN 9
#define LINKS (const char *)("</dev/mfg>;rt=ipso:dev-mfg;ct=\"0\",</dev/mdl>;rt=ipso:dev-mdl;ct=\"0\",</dev/bat>;rt=ipso:dev-bat;ct=\"0\",</pwr/0/w>;rt=ipso:pwr-w;ct=\"0\",</pwr/0/rel>;rt=ipso:pwr-rel;ct=\"0\",</sen/temp>;rt=ucum:Cel;ct=\"0\"")
#define LINKS_LEN 200
#define RD_PATH (const char *)("rd")

extern void stop_pgm();

/* Function templates */
void svr_send_msg(sn_coap_hdr_s *coap_hdr_ptr);
int svr_receive_msg(char *buf);
static void svr_msg_handler(char *msg, int len);
void svr_handle_request(sn_coap_hdr_s *coap_packet_ptr);
void svr_handle_request_mfg(sn_coap_hdr_s *coap_packet_ptr);
void svr_handle_request_mdl(sn_coap_hdr_s *coap_packet_ptr);
void svr_handle_request_bat(sn_coap_hdr_s *coap_packet_ptr);
void svr_handle_request_pwr(sn_coap_hdr_s *coap_packet_ptr);
void svr_handle_request_rel(sn_coap_hdr_s *coap_packet_ptr);
void svr_handle_request_temp(sn_coap_hdr_s *coap_packet_ptr);
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
char res_rel = '1';
char *reg_location;
int8_t reg_location_len;

#ifdef USE_EDTLS
/* eDTLS related globals*/
uint8_t edtls_connection_status;
uint8_t edtls_session_id;
static uint8_t 	edtls_psk_key[16] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6'};
static uint16_t edtls_psk_key_id = 0x0f0f;

#endif


/*****************************************************/
/* This is called from main to start the CoAP server */
/*****************************************************/
int svr_ipv6(void)
{
	/* Local variables */
	char buf[BUFLEN];
	int rcv_size=0;
	registration_info_t endpoint_info;
#ifdef USE_EDTLS
	uint8_t i = 0;
	sn_edtls_data_buffer_t edtls_buffer_s;
	sn_edtls_address_t edtls_server_address_s;

	memset(&edtls_server_address_s, 0, sizeof(edtls_server_address_s));
#endif

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
	sn_coap_protocol_init(&own_alloc, &own_free, &tx_function);

	/* Initialize random MID */
	srand (time(NULL));
	current_mid = rand() % 10000;

	/* eDTLS init and connection */
#ifdef USE_EDTLS
	sn_edtls_libraray_initialize();

	edtls_pre_shared_key_set(edtls_psk_key, edtls_psk_key_id);
	edtls_server_address_s.socket = sock_server;
	edtls_session_id = sn_edtls_connect(&edtls_server_address_s);
#ifdef HAVE_DEBUG
			printf("Waiting for eDTLS to connect..\n");
#endif

	/* Wait for the eDTLS to connect */
	while((edtls_connection_status != EDTLS_CONNECTION_OK) && (i < MAX_CONNECTING_TIME))
	{
		usleep(5000);
		i++;
		rcv_size = svr_receive_msg(buf);
		if(rcv_size)
		{
			edtls_buffer_s.buff = (uint8_t*)buf;
			edtls_buffer_s.len = rcv_size;
			sn_edtls_parse_data(edtls_session_id, &edtls_buffer_s);
			memset(buf, 0, BUFLEN);
		}
	}

	/* If connection failed, then return */
	if(edtls_connection_status == EDTLS_CONNECTION_CLOSED || edtls_connection_status == EDTLS_CONNECTION_FAILED)
	{
#ifdef HAVE_DEBUG
		printf("eDTLS connection failed!\n");
#endif
		return 0;
	}
#ifdef HAVE_DEBUG
		printf("eDTLS connected!\n");
#endif
#endif

	/* Register with NSP */
#ifdef HAVE_DEBUG
	printf("h: %s\n", EP);
	printf("rt: %s\n", EP_TYPE);
	printf("links: %s\n", LINKS);
#endif
	endpoint_info.endpoint_ptr = (uint8_t *)EP;
	endpoint_info.endpoint_len = EP_LEN;
	endpoint_info.endpoint_type_ptr = (uint8_t *)EP_TYPE;
	endpoint_info.endpoint_type_len = EP_TYPE_LEN;
	endpoint_info.links_ptr = (uint8_t *)LINKS;
	endpoint_info.links_len = LINKS_LEN;

	nsp_register(&endpoint_info);

	/* 				Main loop.				*/
	/* Listen and process incoming messages */
	while (1)
	{
		usleep(100);
		memset(buf, 0, BUFLEN);
		rcv_size = svr_receive_msg(buf);
#ifdef USE_EDTLS
		edtls_buffer_s.buff = (uint8_t*)buf;
		edtls_buffer_s.len = rcv_size;
		sn_edtls_parse_data(edtls_session_id, &edtls_buffer_s);
		svr_msg_handler((char*)edtls_buffer_s.buff, edtls_buffer_s.len);
#else
		svr_msg_handler(buf, rcv_size);
#endif
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
#ifdef USE_EDTLS
	printf("eDTLS RX %s.%d [%d B]\n", rcv_in6_addr, ntohs(sa_dst.sin6_port), rcv_size);
#else
	printf("\nRX %s.%d [%d B] - ", rcv_in6_addr, ntohs(sa_dst.sin6_port), rcv_size);
#endif
#endif
  }

 return rcv_size;
}


void svr_send_msg(sn_coap_hdr_s *coap_hdr_ptr)
{
	uint8_t 	*message_ptr = NULL;
	uint16_t 	message_len	= 0;
	char dst_in6_addr[32];
#ifdef USE_EDTLS
	sn_edtls_data_buffer_t edtls_data_s;
#endif

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

#ifdef USE_EDTLS
	edtls_data_s.buff = message_ptr;
	edtls_data_s.len = message_len;
	sn_edtls_write_data(edtls_session_id, &edtls_data_s);

#else
	/* Send the message */
	if (sendto(sock_server, message_ptr, message_len, 0, (const struct sockaddr *)&sa_dst, slen_sa_dst)==-1)
				stop_pgm("sendto() failed");
#endif


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
#ifdef USE_EDTLS
	sn_edtls_data_buffer_t edtls_buffer_s;
#endif

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


#ifdef USE_EDTLS
	edtls_buffer_s.buff = (uint8_t*)buf;
	edtls_buffer_s.len = rcv_size;
	sn_edtls_parse_data(edtls_session_id, &edtls_buffer_s);
	coap_packet_ptr = sn_coap_parser(edtls_buffer_s.len, edtls_buffer_s.buff, &coap_version);

#else
	coap_packet_ptr = sn_coap_parser(rcv_size, (uint8_t*)buf, &coap_version);
#endif

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
				sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
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
	if (memcmp(coap_packet_ptr->uri_path_ptr, RES_MFG, strlen(RES_MFG)) == 0)
		svr_handle_request_mfg(coap_packet_ptr);
	else if (memcmp(coap_packet_ptr->uri_path_ptr, RES_MDL, strlen(RES_MDL)) == 0)
		svr_handle_request_mdl(coap_packet_ptr);
	else if (memcmp(coap_packet_ptr->uri_path_ptr, RES_BAT, strlen(RES_BAT)) == 0)
		svr_handle_request_bat(coap_packet_ptr);
	else if (memcmp(coap_packet_ptr->uri_path_ptr, RES_PWR, strlen(RES_PWR)) == 0)
		svr_handle_request_pwr(coap_packet_ptr);
	else if (memcmp(coap_packet_ptr->uri_path_ptr, RES_REL, strlen(RES_REL)) == 0)
		svr_handle_request_rel(coap_packet_ptr);
	else if (memcmp(coap_packet_ptr->uri_path_ptr, RES_TEMP, strlen(RES_TEMP)) == 0)
		svr_handle_request_temp(coap_packet_ptr);
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


void svr_handle_request_mfg(sn_coap_hdr_s *coap_packet_ptr)
{
	sn_coap_hdr_s *coap_res_ptr;
	if (coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
	{
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_CONTENT);
		coap_res_ptr->content_type_ptr = &text_plain;
		coap_res_ptr->content_type_len = sizeof(text_plain);
		coap_res_ptr->payload_len = strlen(RES_MFG_VAL);
		coap_res_ptr->payload_ptr = own_alloc(coap_res_ptr->payload_len);
		if(!coap_res_ptr->payload_ptr)
			return;
		memcpy(coap_res_ptr->payload_ptr, RES_MFG_VAL, coap_res_ptr->payload_len);
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

void svr_handle_request_mdl(sn_coap_hdr_s *coap_packet_ptr)
{
	sn_coap_hdr_s *coap_res_ptr;
	if (coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
	{
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_CONTENT);
		coap_res_ptr->content_type_ptr = &text_plain;
		coap_res_ptr->content_type_len = sizeof(text_plain);
		coap_res_ptr->payload_len = strlen(RES_MDL_VAL);
		coap_res_ptr->payload_ptr = own_alloc(coap_res_ptr->payload_len);
		if(!coap_res_ptr->payload_ptr)
			return;
		memcpy(coap_res_ptr->payload_ptr, RES_MDL_VAL, coap_res_ptr->payload_len);
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

void svr_handle_request_bat(sn_coap_hdr_s *coap_packet_ptr)
{
	sn_coap_hdr_s *coap_res_ptr;
	if (coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
	{
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_CONTENT);
		coap_res_ptr->content_type_ptr = &text_plain;
		coap_res_ptr->content_type_len = sizeof(text_plain);
		coap_res_ptr->payload_len = strlen(RES_BAT_VAL);
		coap_res_ptr->payload_ptr = own_alloc(coap_res_ptr->payload_len);
		if(!coap_res_ptr->payload_ptr)
			return;
		memcpy(coap_res_ptr->payload_ptr, RES_BAT_VAL, coap_res_ptr->payload_len);
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

void svr_handle_request_pwr(sn_coap_hdr_s *coap_packet_ptr)
{
	sn_coap_hdr_s *coap_res_ptr;
	if (coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
	{
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_CONTENT);
		coap_res_ptr->content_type_ptr = &text_plain;
		coap_res_ptr->content_type_len = sizeof(text_plain);
		if (res_rel == '1') {
			coap_res_ptr->payload_len = strlen(RES_PWR_VAL);
			coap_res_ptr->payload_ptr = own_alloc(coap_res_ptr->payload_len);
			if(!coap_res_ptr->payload_ptr)
				return;
			memcpy(coap_res_ptr->payload_ptr, RES_PWR_VAL, coap_res_ptr->payload_len);
		} else {
			coap_res_ptr->payload_len = strlen(RES_PWR_VAL_OFF);
			coap_res_ptr->payload_ptr = own_alloc(coap_res_ptr->payload_len);
			if(!coap_res_ptr->payload_ptr)
				return;
			memcpy(coap_res_ptr->payload_ptr, RES_PWR_VAL_OFF, coap_res_ptr->payload_len);
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

void svr_handle_request_rel(sn_coap_hdr_s *coap_packet_ptr)
{
	sn_coap_hdr_s *coap_res_ptr;
	if (coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
	{
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_CONTENT);
		coap_res_ptr->content_type_ptr = &text_plain;
		coap_res_ptr->content_type_len = sizeof(text_plain);
		coap_res_ptr->payload_len = 1;
		coap_res_ptr->payload_ptr = own_alloc(coap_res_ptr->payload_len);
		if(!coap_res_ptr->payload_ptr)
			return;
		memcpy(coap_res_ptr->payload_ptr, &res_rel, 1);
		//coap_res_ptr->payload_ptr[0] = res_rel;
		svr_send_msg(coap_res_ptr);
		return;
	} else if (coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_PUT)
		{
			if (coap_packet_ptr->payload_ptr && coap_packet_ptr->payload_len < 2)
			{
				res_rel = coap_packet_ptr->payload_ptr[0];
			}
			coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_CHANGED);
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

void svr_handle_request_temp(sn_coap_hdr_s *coap_packet_ptr)
{
	sn_coap_hdr_s *coap_res_ptr;
	if (coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
	{
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_CONTENT);
		coap_res_ptr->content_type_ptr = &text_plain;
		coap_res_ptr->content_type_len = sizeof(text_plain);
		coap_res_ptr->payload_len = strlen(RES_TEMP_VAL);
		coap_res_ptr->payload_ptr = own_alloc(coap_res_ptr->payload_len);
		if(!coap_res_ptr->payload_ptr)
			return;
		memcpy(coap_res_ptr->payload_ptr, RES_TEMP_VAL, coap_res_ptr->payload_len);
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

#ifdef USE_EDTLS
/* eDTLS helper functions */

/* eDTLS allocation function */
void *edtls_malloc(uint16_t alloc_size)
{
	return own_alloc(alloc_size);
}

/* eDTLS free function */
void edtls_free(void *mem_ptr)
{
	own_free(mem_ptr);
}

/* eDTLS sending function */
uint8_t edtls_tx(uint8_t *data_ptr, uint16_t data_len, sn_edtls_address_t *dst_addr)
{
	char dst_in6_addr[32];

	/* Set NSP address and port */
	sa_dst.sin6_family = AF_INET6;
	sa_dst.sin6_port = htons(arg_dport);
	if (inet_pton(AF_INET6, arg_dst, &(sa_dst.sin6_addr))==0)
		stop_pgm("inet_ntop() failed");;

	inet_ntop(AF_INET6, &(sa_dst.sin6_addr),dst_in6_addr,INET6_ADDRSTRLEN);

#ifdef HAVE_DEBUG
	printf("eDTLS TX [%d B]\n",data_len);
#endif

	/* Send the message */
	if (sendto(sock_server, data_ptr, data_len, 0, (const struct sockaddr *)&sa_dst, slen_sa_dst)==-1)
				stop_pgm("sendto() failed");

	return 1;
}

/* eDTLS random generation function 	*/
/* Used to generate client hello random */
/* fields and sequence numbers.			*/
uint8_t edtls_random()
{
	return rand();
}

/* eDTLS registration status function 				*/
/* eDTLS library returns status during registration */
/* EDTLS_CONNECTION_FAILED = 0						*/
/* EDTLS_CONNECTION_OK = 1							*/
/* EDTLS_CONNECTION_CLOSED = 2 						*/
void edtls_registration_status(uint8_t status, int16_t session_id)
{
	edtls_connection_status = status;
}

#endif
