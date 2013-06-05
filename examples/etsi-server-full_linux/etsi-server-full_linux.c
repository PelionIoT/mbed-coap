/**
 * \file 	etsi-server_full-linux.c
 *
 * \brief	ETSI plugtest test server.
 *
 * \author 	Tero Heinonen <tero.heinonen@sensinode.com>
 *
 */
#if 0
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <signal.h> /* For SIGIGN and SIGINT */
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include "arguments.h"

/* libCoap includes */
#include "sn_nsdl.h"
#include "sn_coap_header.h"
#include "sn_coap_protocol.h"
#include "sn_nsdl_lib.h"

#include "resource_generation_help.h"

#define BUFLEN 1024

/* Resource paths and registration parameters */
static uint8_t res_test[] = {"test"};
static uint8_t res_long_path[] = {"seg1/seg2/seg3"};
static uint8_t res_location_path[] = {"location1/location2/location3"};
static uint8_t res_location_query[] = {"location-query"};
static uint8_t res_query[] = {"query"};
static uint8_t res_separate[] = {"separate"};
static uint8_t res_large[] = {"large"};
static uint8_t res_large_update[] = {"large-update"};
//static uint8_t res_large_create[] = {"large-create"};  //Not created in startup
static uint8_t res_obs[] = {"obs"};
static uint8_t res_multi_format[] = {"multi-format"};
static uint8_t res_link1[] = {"link1"};
static uint8_t res_link2[] = {"link2"};
static uint8_t res_link3[] = {"link3"};
static uint8_t res_path[] = {"path"};
static uint8_t res_path_sub1[] = {"path/sub1"};
static uint8_t res_path_sub2[] = {"path/sub2"};
static uint8_t res_path_sub3[] = {"path/sub3"};
static uint8_t res_alternate[] = {"alternate"};

static uint8_t resource_payload[20] = {"this is the payload!"};
static uint8_t block_payload[243] = {"Ensin lähes tuntemattoman miesporukan mökissä, joita voisi kutsua lähinnä maaalaisjunteiksi, mutta onneksi tajusin hyvissä ajoin ennakoida tilanteen ja ostin meille hotellihuoneen Levin keskustasta, jossa vietimme Juhan kanssa loppuajan."};

//static uint8_t ep[] = {"nsdl-c-plugtest"};
//static uint8_t ep_type[] = {"PlugtestServer"};
//static uint8_t lifetime_ptr[] = {"1200"};
static uint8_t res_type_test[] = {"test"};

extern void stop_pgm();

/* Function templates */
int16_t svr_receive_msg(uint8_t *buf);
void *own_alloc(uint16_t size);
void own_free(void* ptr);
uint8_t tx_function(sn_nsdl_capab_e protocol, uint8_t *data_ptr, uint16_t data_len, sn_nsdl_addr_s *address_ptr);
uint8_t rx_function(sn_coap_hdr_s *coap_header, sn_nsdl_addr_s *address_ptr);
static void ctrl_c_handle_function(void);
typedef void (*signalhandler_t)(int); /* Function pointer type for ctrl-c */
static void coap_exec_poll_function(void);
static uint8_t general_resource_cb(sn_coap_hdr_s *coap_ptr, sn_nsdl_addr_s *address, sn_proto_info_s * proto);
static int8_t compare_uripaths(sn_coap_hdr_s *coap_header, const uint8_t *uri_path_to_compare);
void print_array(uint8_t *ptr, uint16_t len);

/* Socket globals */
static struct sockaddr_in6 sa_dst, sa_src;
static int sock_server, slen_sa_dst=sizeof(sa_dst);

/* Thread globals */
static	pthread_t 	coap_exec_thread 				= 0; /* Thread for coap_exec-function */

/* CoAP related globals*/
uint16_t current_mid = 0;
uint8_t	 text_plain = COAP_CT_TEXT_PLAIN;
uint8_t	 link_format = COAP_CT_LINK_FORMAT;

uint8_t nsp_registered = 0;

/* Resource related globals*/
char relay_state = '1';
uint8_t *reg_location = 0;
int8_t reg_location_len;
uint8_t nsp_addr[16];
uint16_t nsp_port;
uint8_t obs_token[8];
uint8_t obs_token_len = 0;

uint8_t obs_number = 0;
uint8_t obs_set = 0;
uint8_t *dynamic_res_payload;
uint16_t dynamic_res_payload_len = 20;


uint16_t message_id = 0x4324;

sn_nsdl_addr_s received_packet_address;

/*****************************************************/
/* This is called from main to start the CoAP server */
/*****************************************************/
int svr_ipv6(void)
{
	/* Local variables */
	uint8_t buf[BUFLEN];
	int16_t rcv_size=0;
	sn_nsdl_mem_s memory_struct;
	sn_nsdl_resource_info_s	*resource_ptr = 0;



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


	/* Initialize the libNsdl */
	memory_struct.sn_nsdl_alloc = &own_alloc;
	memory_struct.sn_nsdl_free = &own_free;

	sn_nsdl_init(&tx_function ,&rx_function, &memory_struct);

	inet_pton(AF_INET6, arg_dst, &nsp_addr);

	set_NSP_address(nsp_addr, arg_dport);

	pthread_create(&coap_exec_thread, NULL, (void *)coap_exec_poll_function, NULL);

	/* Create resources */
	resource_ptr = own_alloc(sizeof(sn_nsdl_resource_info_s));
	if(!resource_ptr)
		return 0;
	memset(resource_ptr, 0, sizeof(sn_nsdl_resource_info_s));

	resource_ptr->resource_parameters_ptr = own_alloc(sizeof(sn_nsdl_resource_parameters_s));
	if(!resource_ptr->resource_parameters_ptr)
	{
		own_free(resource_ptr);
		return 0;
	}
	memset(resource_ptr->resource_parameters_ptr, 0, sizeof(sn_nsdl_resource_parameters_s));

	CREATE_STATIC_RESOURCE(resource_ptr, sizeof(res_test)-1, (uint8_t*)res_test, sizeof(res_type_test)-1, (uint8_t*)res_type_test, resource_payload, sizeof(resource_payload));
	CREATE_STATIC_RESOURCE(resource_ptr, sizeof(res_long_path)-1, (uint8_t*)res_long_path, sizeof(res_type_test)-1, (uint8_t*)res_type_test, resource_payload, sizeof(resource_payload));
	CREATE_STATIC_RESOURCE(resource_ptr, sizeof(res_location_path)-1, (uint8_t*)res_location_path, sizeof(res_type_test)-1, (uint8_t*)res_type_test, resource_payload, sizeof(resource_payload));
	CREATE_STATIC_RESOURCE(resource_ptr, sizeof(res_location_query)-1, (uint8_t*)res_location_query, sizeof(res_type_test)-1, (uint8_t*)res_type_test, resource_payload, sizeof(resource_payload));
	CREATE_STATIC_RESOURCE(resource_ptr, sizeof(res_query)-1, (uint8_t*)res_query, sizeof(res_type_test)-1, (uint8_t*)res_type_test, resource_payload, sizeof(resource_payload));
	CREATE_STATIC_RESOURCE(resource_ptr, sizeof(res_separate)-1, (uint8_t*)res_separate, sizeof(res_type_test)-1, (uint8_t*)res_type_test, resource_payload, sizeof(resource_payload));
	CREATE_STATIC_RESOURCE(resource_ptr, sizeof(res_large)-1, (uint8_t*)res_large, sizeof(res_type_test)-1, (uint8_t*)res_type_test, block_payload, sizeof(block_payload));
	CREATE_STATIC_RESOURCE(resource_ptr, sizeof(res_large_update)-1, (uint8_t*)res_large_update, sizeof(res_type_test)-1, (uint8_t*)res_type_test, block_payload, sizeof(block_payload));
	CREATE_DYNAMIC_RESOURCE(resource_ptr, sizeof(res_obs)-1, (uint8_t*) res_obs, sizeof(res_type_test)-1, (uint8_t*)res_type_test, 1, &general_resource_cb) /* Observable resource */
	CREATE_STATIC_RESOURCE(resource_ptr, sizeof(res_multi_format)-1, (uint8_t*)res_multi_format, sizeof(res_type_test)-1, (uint8_t*)res_type_test, resource_payload, sizeof(resource_payload));
	CREATE_STATIC_RESOURCE(resource_ptr, sizeof(res_link1)-1, (uint8_t*)res_link1, sizeof(res_type_test)-1, (uint8_t*)res_type_test, resource_payload, sizeof(resource_payload));
	CREATE_STATIC_RESOURCE(resource_ptr, sizeof(res_link2)-1, (uint8_t*)res_link2, sizeof(res_type_test)-1, (uint8_t*)res_type_test, resource_payload, sizeof(resource_payload));
	CREATE_STATIC_RESOURCE(resource_ptr, sizeof(res_link3)-1, (uint8_t*)res_link3, sizeof(res_type_test)-1, (uint8_t*)res_type_test, resource_payload, sizeof(resource_payload));
	CREATE_STATIC_RESOURCE(resource_ptr, sizeof(res_path)-1, (uint8_t*)res_path, sizeof(res_type_test)-1, (uint8_t*)res_type_test, resource_payload, sizeof(resource_payload));
	CREATE_STATIC_RESOURCE(resource_ptr, sizeof(res_path_sub1)-1, (uint8_t*)res_path_sub1, sizeof(res_type_test)-1, (uint8_t*)res_type_test, resource_payload, sizeof(resource_payload));
	CREATE_STATIC_RESOURCE(resource_ptr, sizeof(res_path_sub2)-1, (uint8_t*)res_path_sub2, sizeof(res_type_test)-1, (uint8_t*)res_type_test, resource_payload, sizeof(resource_payload));
	CREATE_STATIC_RESOURCE(resource_ptr, sizeof(res_path_sub3)-1, (uint8_t*)res_path_sub3, sizeof(res_type_test)-1, (uint8_t*)res_type_test, resource_payload, sizeof(resource_payload));
	CREATE_STATIC_RESOURCE(resource_ptr, sizeof(res_alternate)-1, (uint8_t*)res_alternate, sizeof(res_type_test)-1, (uint8_t*)res_type_test, resource_payload, sizeof(resource_payload));

	dynamic_res_payload = malloc(dynamic_res_payload_len);
	memcpy(dynamic_res_payload, resource_payload, dynamic_res_payload_len);

	own_free(resource_ptr->resource_parameters_ptr);
	own_free(resource_ptr);

	/* 				Main loop.				*/
	/* Listen and process incoming messages */

	received_packet_address.addr_len = 16;
	received_packet_address.addr_ptr = nsp_addr;
	received_packet_address.socket_information = 0;
	received_packet_address.type = SN_NSDL_ADDRESS_TYPE_IPV6;

	sleep(1);

	while (1)
	{
		usleep(100);
		memset(buf, 0, BUFLEN);
		rcv_size = svr_receive_msg(buf);
		if(rcv_size > 0)
		{
			received_packet_address.port = ntohs(sa_dst.sin6_port);
			nsp_port = received_packet_address.port;
			sn_nsdl_process_coap(buf, rcv_size, &received_packet_address);
		}
	}
	return 0;
}

/****************************/
/* Message receive function */
/****************************/
int16_t svr_receive_msg(uint8_t *buf)
{
  char rcv_in6_addr[32];
  int16_t rcv_size=0;
  uint16_t temp_len;
  uint16_t i;

  memset(rcv_in6_addr,0,32);

  if ((rcv_size=recvfrom(sock_server, buf, BUFLEN, 0, (struct sockaddr *)&sa_dst, (socklen_t*)&slen_sa_dst))==-1)
		stop_pgm("recvfrom()");
  else
  {
	inet_ntop(AF_INET6, &(sa_dst.sin6_addr),rcv_in6_addr,INET6_ADDRSTRLEN);
#ifdef HAVE_DEBUG
	printf("\nRX %s.%d [%d B] - ", rcv_in6_addr, ntohs(sa_dst.sin6_port), rcv_size);

	if(rcv_size > 40)
		temp_len = 40;
	else
		temp_len = rcv_size;

	for(i=0;i<temp_len;i++)
		printf("%#x ", *(buf+i));
	printf("\n");

#endif
  }

 return rcv_size;
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
	uint16_t i = 0;
	uint8_t temp_len;
	/* Set NSP address and port */
	sa_dst.sin6_family = AF_INET6;
	sa_dst.sin6_port = htons(address_ptr->port);
	if (inet_pton(AF_INET6, arg_dst, &(sa_dst.sin6_addr))==0)
		stop_pgm("inet_ntop() failed");

#ifdef HAVE_DEBUG
	printf("libNSDL TX [%d B] - ",data_len);
	if(data_len > 40)
		temp_len = 40;
	else
		temp_len = data_len;

	for(i=0;i<temp_len;i++)
		printf("%#x ", *(data_ptr+i));
	printf("\n");
#endif
	/* Send the message */
	if (sendto(sock_server, data_ptr, data_len, 0, (const struct sockaddr *)&sa_dst, slen_sa_dst)==-1)
				stop_pgm("sendto() failed");
	return 1;
}

uint8_t rx_function(sn_coap_hdr_s *coap_header, sn_nsdl_addr_s *address_ptr)
{
	if(!coap_header)
		return 0;
#ifdef HAVE_DEBUG
		printf("rx callback %d bytes:" ,coap_header->payload_len);
#endif
	return 0;
}

static void ctrl_c_handle_function(void)
{
#ifdef HAVE_DEBUG
	printf("Pressed ctrl-c\n");
#endif
	exit(1);
}

static void coap_exec_poll_function(void)
{
	static uint32_t ns_system_time = 1;
	static uint8_t i = 0;

	while(1)
	{
		sleep(1);
		sn_nsdl_exec(ns_system_time);
		ns_system_time++;

		/* If observation received, start sending notifications */
		if(obs_set)
		{
			if(i >= 5)
			{
				if(obs_token_len)
					sn_nsdl_send_observation_notification(obs_token, obs_token_len, dynamic_res_payload, dynamic_res_payload_len, &obs_number, 1);
				else
					sn_nsdl_send_observation_notification(0, obs_token_len, dynamic_res_payload, dynamic_res_payload_len, &obs_number, 1);
				obs_number++;
				i = 0;
			}
			else
				i++;
		}
	}
}


static uint8_t general_resource_cb(sn_coap_hdr_s *received_coap_ptr, sn_nsdl_addr_s *address, sn_proto_info_s * proto)
{
	sn_coap_hdr_s *coap_res_ptr = 0;
	uint8_t i = 0;
	static uint8_t resource_exist = 1;

	printf("General callback\n");

	if(resource_exist)
	{
		if (received_coap_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
		{
			coap_res_ptr = sn_coap_build_response(received_coap_ptr, COAP_MSG_CODE_RESPONSE_CONTENT);
			if(coap_res_ptr->msg_id == 0)
				coap_res_ptr->msg_id = message_id++;
			coap_res_ptr->content_type_ptr = &text_plain;
			coap_res_ptr->content_type_len = sizeof(text_plain);

			/* Obs */
			coap_res_ptr->options_list_ptr = own_alloc(sizeof(sn_coap_options_list_s));
			if(!coap_res_ptr->options_list_ptr)
				sn_coap_parser_release_allocated_coap_msg_mem(coap_res_ptr);

			memset(coap_res_ptr->options_list_ptr, 0, sizeof(sn_coap_options_list_s));

			obs_number ++;

			coap_res_ptr->options_list_ptr->observe_len = 1;
			coap_res_ptr->options_list_ptr->observe_ptr = &obs_number;
			obs_number++;

			if(received_coap_ptr->options_list_ptr)
			{
				if(received_coap_ptr->options_list_ptr->observe)
				{
					printf("Observe\n");
					set_NSP_address(nsp_addr, nsp_port);
					obs_set = 1;
				}
				else
					obs_set = 0;
			}
			if(received_coap_ptr->token_ptr)
			{
				memset(obs_token, 0, 8);
				memcpy(obs_token, received_coap_ptr->token_ptr, received_coap_ptr->token_len);
				obs_token_len = received_coap_ptr->token_len;
			}
			coap_res_ptr->payload_len = dynamic_res_payload_len;
			coap_res_ptr->payload_ptr = dynamic_res_payload;
		}

		else if (received_coap_ptr->msg_code == COAP_MSG_CODE_REQUEST_POST)
		{
			coap_res_ptr = sn_coap_build_response(received_coap_ptr, COAP_MSG_CODE_RESPONSE_CHANGED);

			dynamic_res_payload_len = received_coap_ptr->payload_len;
			free(dynamic_res_payload);
			dynamic_res_payload = malloc(dynamic_res_payload_len);
			memcpy(dynamic_res_payload, received_coap_ptr->payload_ptr, received_coap_ptr->payload_len);

			if(received_coap_ptr->token_ptr)
			{
				memset(obs_token, 0, 8);
				memcpy(obs_token, received_coap_ptr->token_ptr, received_coap_ptr->token_len);
				obs_token_len = received_coap_ptr->token_len;
			}

		}

		else if (received_coap_ptr->msg_code == COAP_MSG_CODE_REQUEST_DELETE)
		{
			coap_res_ptr = sn_coap_build_response(received_coap_ptr, COAP_MSG_CODE_RESPONSE_DELETED);

			obs_set = 0;
			resource_exist = 0;
		}

		else if (received_coap_ptr->msg_code == COAP_MSG_CODE_REQUEST_PUT)
		{
			coap_res_ptr = sn_coap_build_response(received_coap_ptr, COAP_MSG_CODE_RESPONSE_CHANGED);

			dynamic_res_payload_len = received_coap_ptr->payload_len;
			free(dynamic_res_payload);
			dynamic_res_payload = malloc(dynamic_res_payload_len);
			memcpy(dynamic_res_payload, received_coap_ptr->payload_ptr, received_coap_ptr->payload_len);

			if(received_coap_ptr->token_ptr)
			{
				memset(obs_token, 0, 8);
				memcpy(obs_token, received_coap_ptr->token_ptr, received_coap_ptr->token_len);
				obs_token_len = received_coap_ptr->token_len;
			}
		}
	}

	/* Resource does not exist */
	else
	{
		if (received_coap_ptr->msg_code == COAP_MSG_CODE_REQUEST_PUT)
		{
			coap_res_ptr = sn_coap_build_response(received_coap_ptr, COAP_MSG_CODE_RESPONSE_CREATED);


			dynamic_res_payload_len = received_coap_ptr->payload_len;
			free(dynamic_res_payload);
			dynamic_res_payload = malloc(dynamic_res_payload_len);
			memcpy(dynamic_res_payload, received_coap_ptr->payload_ptr, received_coap_ptr->payload_len);

			if(received_coap_ptr->token_ptr)
			{
				memset(obs_token, 0, 8);
				memcpy(obs_token, received_coap_ptr->token_ptr, received_coap_ptr->token_len);
				obs_token_len = received_coap_ptr->token_len;
			}

		}
		else
		{
			printf("Resource not found\n");
			coap_res_ptr = sn_coap_build_response(received_coap_ptr, COAP_MSG_CODE_RESPONSE_NOT_FOUND);
		}
	}


	/* Send response */
	sn_nsdl_send_coap_message(address, coap_res_ptr);

	/* Free memory */
	if(coap_res_ptr)
	{
		if(coap_res_ptr->token_ptr)
		{
			own_free(coap_res_ptr->token_ptr);
		}

		if(coap_res_ptr->options_list_ptr)
			own_free(coap_res_ptr->options_list_ptr);
		own_free(coap_res_ptr);
	}
	return 0;
}

static int8_t compare_uripaths(sn_coap_hdr_s *coap_header, const uint8_t *uri_path_to_compare)
{
    if(memcmp(coap_header->uri_path_ptr,&uri_path_to_compare[0], coap_header->uri_path_len) == 0)
	{
		return 1;
	}
	return 0;
}

void print_array(uint8_t *ptr, uint16_t len)
{
	uint16_t i = 0;

	while(i < len)
	{
		printf("%x:", *(ptr+i));
		i++;
	}
	printf("\n");
}
#endif
