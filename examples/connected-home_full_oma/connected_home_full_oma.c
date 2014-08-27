/**
 * \file 	connected-home_full_ipv4.c
 *
 * \brief	Connected Home CoAP Server. Emulates a power node.
 *
 * \author 	Zach Shelby <zach@sensinode.com>
 *
 */

#if 1

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
#include "bootstrap_certificates.h"

#include "sn_edtls_lib.h"
#include "sn_aes.h"
#define MAX_CONNECTING_TIME 200

#define BUFLEN 1024

/* Resource paths and registration parameters */
static uint8_t res_mgf[] = {"dev/mfg"};
static uint8_t res_mgf_val[] = {"Sensinode"};
static uint8_t res_mdl[] = {"dev/mdl"};
static uint8_t res_mdl_val[] = {"NSDL-C power node"};
static uint8_t res_bat[] = {"dev/bat"};
static uint8_t res_bat_val[] = {'1'};
static uint8_t res_pwr[] = {"pwr/0/w"};
static uint8_t res_pwr_val[] = {"80"};
static uint8_t res_pwr_val_off[] = {"0"};
static uint8_t res_rel[] = {"pwr/0/rel"};
static uint8_t res_temp[] = {"sen/temp"};
static uint8_t res_temp_val[] = {"25.4"};
static uint8_t res_type_test[] = {"t"};

static uint8_t query[] = "nodesec-001";
static uint8_t ep_type[] = {"PowerNode"};
static uint8_t lifetime_ptr[] = {"1200"};

static uint8_t oma = 0;

extern void stop_pgm();

/* Function templates */
int16_t svr_receive_msg(void);
void *own_alloc(uint16_t size);
void own_free(void* ptr);
uint8_t tx_function(sn_nsdl_capab_e protocol, uint8_t *data_ptr, uint16_t data_len, sn_nsdl_addr_s *address_ptr);
uint8_t rx_function(sn_coap_hdr_s *coap_header, sn_nsdl_addr_s *address_ptr);
static void ctrl_c_handle_function(void);
typedef void (*signalhandler_t)(int); /* Function pointer type for ctrl-c */
static void coap_exec_poll_function(void);
static uint8_t relay_resource_cb(sn_coap_hdr_s *coap_ptr, sn_nsdl_addr_s *address, sn_proto_info_s * proto);
static uint8_t general_resource_cb(sn_coap_hdr_s *coap_ptr, sn_nsdl_addr_s *address, sn_proto_info_s * proto);
static int8_t compare_uripaths(sn_coap_hdr_s *coap_header, const uint8_t *uri_path_to_compare);
void print_array(uint8_t *ptr, uint16_t len);
void send_ack(sn_coap_hdr_s *received_coap_ptr, sn_nsdl_addr_s *address);
uint8_t edtls_tx(uint8_t *data_ptr, uint16_t data_len, sn_edtls_address_t *dst_addr);
void edtls_registration_status(uint8_t status, int16_t session_id);
static int16_t do_edtls_handshake(sn_edtls_address_t *edtls_address);
void oma_status(sn_nsdl_oma_server_info_t *server_info_ptr);

/* Socket globals */
static struct sockaddr_in sa_dst, sa_src;
static int sock_server, slen_sa_dst=sizeof(sa_dst);

/* Thread globals */
static	pthread_t 	coap_exec_thread 				= 0; /* Thread for coap_exec-function */
static	pthread_t 	socket_read_thread 				= 0; /* Thread for socket reading */

/* CoAP related globals*/
uint16_t current_mid = 0;
uint8_t	 text_plain = COAP_CT_TEXT_PLAIN;
uint8_t	 link_format = COAP_CT_LINK_FORMAT;

/* eDTLS related globals*/
uint8_t edtls_connection_status;
uint8_t bs_edtls_connection_status;

int16_t edtls_session_id;
int16_t bs_edtls_session_id;

static edtls_certificate_chain_entry_t certificate_chain_entry;

/* Resource related globals*/
uint8_t relay_state = '1';

uint8_t nsp_addr[16];

uint8_t obs_token[8];
uint8_t obs_token_len = 0;

uint8_t obs_number = 0;

/* Delayed response globals */
static uint8_t delayed_token[8];
static uint8_t delayed_token_len = 0;
static sn_coap_msg_type_e delayed_msg_type;
static uint8_t delayed_response_cnt = 0;

/* Common globals */
uint8_t domain[] = {"domain"};
static uint32_t ns_system_time = 1;
static volatile int16_t rcv_size=0;

static uint8_t buf[BUFLEN];
static sn_edtls_address_t edtls_server_address;

sn_nsdl_addr_s received_packet_address;
uint8_t received_address[4];

/*****************************************************/
/* This is called from main to start the CoAP server */
/*****************************************************/
int svr_ipv4(void)
{
	/* Local variables */

	sn_nsdl_mem_s memory_struct;
	sn_nsdl_ep_parameters_s *endpoint_ptr = 0;
	sn_nsdl_resource_info_s	*resource_ptr = 0;

	/* eDTLS related variables */
	sn_edtls_data_buffer_t edtls_buffer_s;

	memset(&edtls_server_address, 0, sizeof(sn_edtls_address_t));

	memset(&received_packet_address, 0, sizeof(sn_nsdl_addr_s));
	received_packet_address.addr_ptr = received_address;

	/* Catch ctrl-c */
	if (signal(SIGINT, (signalhandler_t)ctrl_c_handle_function) == SIG_ERR)
	{
		printf("Error with SIGINT: %s\n", strerror(errno));
		return -1;
	}
	printf("\nCoAP server\nport: %i\n", arg_port);

	/* Open the server socket*/
	if ((sock_server=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
		stop_pgm("socket() error");

	/* Init the listen port addr*/
	memset((char *) &sa_src, 0, sizeof(sa_src));
	sa_src.sin_family = AF_INET;

	sa_src.sin_port = htons(arg_port);

	/* Listen to the port */
	sa_src.sin_addr.s_addr = INADDR_ANY;
	if (bind(sock_server, (struct sockaddr *) &sa_src, sizeof(sa_src))==-1)
		stop_pgm("bind() error");


	/* Initialize the libNsdl */
	memory_struct.sn_nsdl_alloc = &own_alloc;
	memory_struct.sn_nsdl_free = &own_free;

	/* This initializes libCoap and libNsdl */
	/* Parameters are function pointers to used memory allocation and free functions in structure */
	/* And used functions for TX and RX purposes. */
	sn_nsdl_init(&tx_function, &rx_function, &memory_struct);

	inet_pton(AF_INET, arg_dst, &nsp_addr);

	pthread_create(&coap_exec_thread, NULL, (void *)coap_exec_poll_function, NULL);
	pthread_create(&socket_read_thread, NULL, (void *)svr_receive_msg, NULL);


	/* Create resources */
	/* Resource struct is used during this process. */
	/* Libraries copies values to own list. resource_ptr can be free'd after resource creations */
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

	/* eDTLS init and connection */
	sn_edtls_library_initialize();

	certificate_chain_entry.certificate_owner = 1;
	certificate_chain_entry.chain_length = 2;

	/* Set Root */
	certificate_chain_entry.certi_chain[0] = bs_trusted_certificate;
	certificate_chain_entry.certi_len[0] = sizeof(bs_trusted_certificate);
	certificate_chain_entry.key_chain[0] = 0;

	certificate_chain_entry.certi_chain[1] = bs_client_certificate;
	certificate_chain_entry.certi_len[1] = sizeof(bs_client_certificate);
	certificate_chain_entry.key_chain[1] = bs_private_key;


	if(edtls_certificate_list_update(&certificate_chain_entry) == 0)
		printf("eDTLS certi updated\n");
	else
	{
		printf("eDTLS certi update failed!!\n");
		return 0;
	}

	/* Set eDTLS socket address - same as NSP address in this case */
	edtls_server_address.socket = sock_server;
	edtls_server_address.port = arg_dport;
	edtls_server_address.address_type = SN_EDTLS_ADDRESS_TYPE_IPV4;
	memcpy(edtls_server_address.address, nsp_addr, 16);

	edtls_session_id = do_edtls_handshake(&edtls_server_address);

	if(edtls_session_id < 0)
	{
		return 0;
	}

	rcv_size = 0;

	sn_nsdl_bs_ep_info_t endpoint_info;
	sn_nsdl_oma_device_t oma_device_setup_ptr;

	oma_device_setup_ptr.error_code = 0;
	oma_device_setup_ptr.sn_oma_device_boot_callback = 0;


	sn_nsdl_addr_s address;

	endpoint_info.device_object = &oma_device_setup_ptr;
	endpoint_info.oma_bs_status_cb = &oma_status;

	endpoint_info.device_object = &oma_device_setup_ptr;

	/* Macro to allocate edpoint_ptr structure for endpoint parameters (name, type and lifetime) */
	INIT_REGISTER_NSDL_ENDPOINT(endpoint_ptr, query, ep_type, lifetime_ptr);

	endpoint_ptr->binding_and_mode = BINDING_MODE_U | BINDING_MODE_Q;


	address.port = arg_dport;
	address.type = SN_NSDL_ADDRESS_TYPE_IPV4;
	address.addr_ptr = nsp_addr;
	address.addr_len = 4;

	printf("bootstrap return %d\n",sn_nsdl_oma_bootstrap(&address, endpoint_ptr, &endpoint_info));


	while (!oma)
	{
		/* If message received.. */
		if(rcv_size > 0)
		{
			/* Set data pointer and -length to edtls_buffer - struct */
			edtls_buffer_s.buff = (uint8_t*)buf;
			edtls_buffer_s.len = rcv_size;
			/* Parse eDTLS data - this moves edtls_buffer_s.buff to the start of the payload and sets edtls_buffer_s.len */
			/* If: 	return value = -1, failure occur during parsing */
			/* 		return value = 0, parsing was OK, no payload to process(handshake message etc.) */
			/*		return value > 0, parsing was OK, payload ready process in NSDL */
			if(sn_edtls_parse_data(edtls_session_id, &edtls_buffer_s) > 0)
			{
				/* If there is payload to process, call sn_nsdl_process_coap() - function */
				sn_nsdl_process_coap(edtls_buffer_s.buff, edtls_buffer_s.len , &received_packet_address);
			}
			rcv_size = 0;
		}
	}

	sn_edtls_disconnect(edtls_session_id);

	omalw_certificate_list_t *crt_ptr = sn_nsdl_get_certificates(0);
	if(!crt_ptr)
		printf("certi get failed\r\n");

	certificate_chain_entry.certi_chain[0] = crt_ptr->certificate_ptr[0];
	certificate_chain_entry.certi_len[0] = crt_ptr->certificate_len[0];

	certificate_chain_entry.certi_chain[1] = crt_ptr->certificate_ptr[1];
	certificate_chain_entry.certi_len[1] = crt_ptr->certificate_len[1];

	certificate_chain_entry.key_chain[1] =crt_ptr->own_private_key_ptr;

	if(edtls_certificate_list_update(&certificate_chain_entry) == 0)
		printf("eDTLS certi updated\n");
	else
	{
		printf("eDTLS certi update failed!!\n");
		return 0;
	}

	/**/
	sleep(5);

	edtls_session_id = do_edtls_handshake(&edtls_server_address);

	if(edtls_session_id == 0)
		return 0;

	/* Macro is used to help creating resources. Fills struct and calls sn_nsdl_create_resource() - function */
	/* Static resources are handled in libNsdl, and application can give some value for them to add to responses */
	CREATE_STATIC_RESOURCE(resource_ptr, sizeof(res_mgf)-1, (uint8_t*) res_mgf, sizeof(res_type_test)-1, (uint8_t*)res_type_test,  (uint8_t*) res_mgf_val, sizeof(res_mgf_val)-1);
	CREATE_STATIC_RESOURCE(resource_ptr, sizeof(res_mdl)-1, (uint8_t*) res_mdl, sizeof(res_type_test)-1, (uint8_t*)res_type_test,  (uint8_t*) res_mdl_val, sizeof(res_mdl_val)-1);

	/* Dynamic resources are processed in callback function that is given in resource creating */
	CREATE_DYNAMIC_RESOURCE(resource_ptr, sizeof(res_bat)-1, (uint8_t*) res_bat, sizeof(res_type_test)-1, (uint8_t*)res_type_test, 1, &general_resource_cb) /* Observable resource */
	CREATE_DYNAMIC_RESOURCE(resource_ptr, sizeof(res_pwr)-1, (uint8_t*) res_pwr, sizeof(res_type_test)-1, (uint8_t*)res_type_test, 0, &general_resource_cb)
	CREATE_DYNAMIC_RESOURCE(resource_ptr, sizeof(res_rel)-1, (uint8_t*) res_rel, sizeof(res_type_test)-1, (uint8_t*)res_type_test, 0, &relay_resource_cb)
	CREATE_DYNAMIC_RESOURCE(resource_ptr, sizeof(res_temp)-1, (uint8_t*) res_temp, sizeof(res_type_test)-1, (uint8_t*)res_type_test, 0, &general_resource_cb)

	/* Register with NSP */

	/* Call sn_nsdl_register_endpoint() to send NSP registration message */
	if(sn_nsdl_register_endpoint(endpoint_ptr) == SN_NSDL_FAILURE)
		printf("NSP registration failed\n");

	/* Free endpoint_ptr */
	CLEAN_REGISTER_NSDL_ENDPOINT(endpoint_ptr);

	/* Free resource_ptr */
	if(resource_ptr->resource_parameters_ptr)
		own_free(resource_ptr->resource_parameters_ptr);
	if(resource_ptr)
		own_free(resource_ptr);

	/* 				Main loop.				*/
	/* Listen and process incoming messages */

	sn_nsdl_oma_device_t device_object_ptr;
	memset(&device_object_ptr, 0, sizeof(sn_nsdl_oma_device_t));

	device_object_ptr.error_code = 1;

	sn_nsdl_create_oma_device_object(&device_object_ptr);

	while (1)
	{
		/* If message received.. */
		if(rcv_size > 0)
		{
			/* Set data pointer and -length to edtls_buffer - struct */
			edtls_buffer_s.buff = (uint8_t*)buf;
			edtls_buffer_s.len = rcv_size;
			/* Parse eDTLS data - this moves edtls_buffer_s.buff to the start of the payload and sets edtls_buffer_s.len */
			/* If: 	return value = -1, failure occur during parsing */
			/* 		return value = 0, parsing was OK, no payload to process(handshake message etc.) */
			/*		return value > 0, parsing was OK, payload ready process in NSDL */
			if(sn_edtls_parse_data(edtls_session_id, &edtls_buffer_s) > 0)
			{
				/* If there is payload to process, call sn_nsdl_process_coap() - function */
				sn_nsdl_process_coap(edtls_buffer_s.buff, edtls_buffer_s.len , &received_packet_address);
			}
			rcv_size = 0;
		}
	}
	return 0;
}

/****************************/
/* Message receive function */
/* Reads socket				*/
/****************************/
int16_t svr_receive_msg(void)
{
  char rcv_in_addr[32];

  memset(rcv_in_addr,0,32);

  while(1)
  {
	  if ((rcv_size=recvfrom(sock_server, buf, BUFLEN, 0, (struct sockaddr *)&sa_dst, (socklen_t*)&slen_sa_dst))==-1)
			stop_pgm("recvfrom()");
	  else
	  {
		inet_ntop(AF_INET, &(sa_dst.sin_addr),rcv_in_addr,INET_ADDRSTRLEN);

		received_packet_address.port = ntohs(sa_dst.sin_port);
		memcpy(received_packet_address.addr_ptr, &sa_dst.sin_addr, 4);
		received_packet_address.type = SN_NSDL_ADDRESS_TYPE_IPV4;
		received_packet_address.addr_len = 4;

		printf("\nRX %s.%d [%d B] - ", rcv_in_addr, ntohs(sa_dst.sin_port), rcv_size);
	  }
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

/* Function needed for libCoap protocol. */
uint8_t tx_function(sn_nsdl_capab_e protocol, uint8_t *data_ptr, uint16_t data_len, sn_nsdl_addr_s *address_ptr)
{

	/* Set NSP address and port */
	sa_dst.sin_family = AF_INET;
	sa_dst.sin_port = htons(address_ptr->port);
	memcpy(&sa_dst.sin_addr, address_ptr->addr_ptr, address_ptr->addr_len);

	sn_edtls_data_buffer_t edtls_data_s;

	printf("libNSDL TX [%d B]\n",data_len);

	edtls_data_s.buff = data_ptr;
	edtls_data_s.len = data_len;

	/* If eDTLS is in use, sn_edtls_write_data() - function handles sending with tx-callback function */
	if(sn_edtls_write_data(edtls_session_id, &edtls_data_s) == EDTLS_FAILURE)
	{
		printf("eDTLS write failed\n");
		return 0;
	}

	return 1;
}

/* RX function for libNsdl. Passes CoAP responses sent from application to this function. Also response to registration message */
uint8_t rx_function(sn_coap_hdr_s *coap_header, sn_nsdl_addr_s *address_ptr)
{

	uint8_t i;

	if(!coap_header)
		return 0;

	printf("RX callback mid:%d\n", coap_header->msg_id);

	/* If message is response to NSP registration */
	if((coap_header->msg_code == COAP_MSG_CODE_RESPONSE_CREATED) && !sn_nsdl_is_ep_registered())
	{
		printf("Registered to NSP: ");
		for(i = 0; i < coap_header->options_list_ptr->location_path_len; i++)
			printf("%c", *(coap_header->options_list_ptr->location_path_ptr+i));
		printf("\n");
	}

	return 0;
}

static void ctrl_c_handle_function(void)
{
	printf("Pressed ctrl-c\n");
	sn_nsdl_unregister_endpoint();
	usleep(100);

	exit(1);
}

static void coap_exec_poll_function(void)
{
	static uint8_t i = 0;
	sn_coap_hdr_s coap_header;

	while(1)
	{
		sleep(1);

		/* nsdl execution function, must be called at least once / second. System time must be increased every second. */
		/* Cleans saved and unused data from libraries. Recommend to run this in same thread with other nsdl - functions */
		sn_nsdl_exec(ns_system_time);
		ns_system_time++;

		/* If observation received, start sending notifications */
		/* This is just example to send notifications to NSP */
		if(obs_token_len)
		{
			if(i >= 10)
			{
				printf("observation message ID %d\n", sn_nsdl_send_observation_notification(obs_token, obs_token_len, res_bat_val, sizeof(res_bat_val), &obs_number, 1, COAP_MSG_TYPE_NON_CONFIRMABLE, 0));
				if(res_bat_val[0] >= '4')
					res_bat_val[0] = '0';
				else
					res_bat_val[0] += 1;

				obs_number++;
				i = 0;
			}
			else
				i++;
		}

		/* Check if reregistration needed */
		if(!(ns_system_time % (uint32_t)20) && ns_system_time)
		{
			printf("reregister!\n");
			sn_nsdl_ep_parameters_s *endpoint_ptr = 0;

			/* Macro to allocate edpoint_ptr structure for endpoint parameters (name, type and lifetime) */
			INIT_REGISTER_NSDL_ENDPOINT(endpoint_ptr, query, ep_type, lifetime_ptr);

			endpoint_ptr->binding_and_mode = BINDING_MODE_U | BINDING_MODE_Q;

			sn_nsdl_update_registration(endpoint_ptr);

			CLEAN_REGISTER_NSDL_ENDPOINT(endpoint_ptr);

		}

		/* Send delayed response to request */
		/* This is just example. When receiving request to sen/temp, application send ack and after few seconds value for this resource */
		if(delayed_response_cnt == 1)
		{
			printf("deleyed response!\n");
			memset(&coap_header, 0, sizeof(sn_coap_hdr_s));

			if(delayed_msg_type == COAP_MSG_TYPE_CONFIRMABLE)
				coap_header.msg_type = COAP_MSG_TYPE_CONFIRMABLE;
			else if(delayed_msg_type == COAP_MSG_TYPE_NON_CONFIRMABLE)
				coap_header.msg_type = COAP_MSG_TYPE_NON_CONFIRMABLE;

			coap_header.msg_code = COAP_MSG_CODE_RESPONSE_CONTENT;

			if(delayed_token_len)
			{
				coap_header.token_len = delayed_token_len;
				coap_header.token_ptr = delayed_token;
				delayed_token_len = 0;
			}

			coap_header.payload_len = sizeof(res_temp_val) - 1;
			coap_header.payload_ptr = res_temp_val;

			sn_nsdl_send_coap_message(&received_packet_address, &coap_header);

			delayed_response_cnt = 0;
		}

		else if(delayed_response_cnt > 1)
			delayed_response_cnt--;
	}
}

/* This is callback for relay resource. When receiving request to "pwr/0/rel" libNsdl calls this */
static uint8_t relay_resource_cb(sn_coap_hdr_s *received_coap_ptr, sn_nsdl_addr_s *address, sn_proto_info_s * proto)
{
	/* Pointer for response message to be sent */
	sn_coap_hdr_s *coap_res_ptr = 0;


	printf("Relay callback\n");

	/* If GET request */
	if (received_coap_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
	{
		/* Allocate memory for the response and fill msg ID, message code, mesasge type and token, if needed */
		coap_res_ptr = sn_coap_build_response(received_coap_ptr, COAP_MSG_CODE_RESPONSE_CONTENT);

		/* Give content type */
		coap_res_ptr->content_type_ptr = &text_plain;
		coap_res_ptr->content_type_len = sizeof(text_plain);
		/* Add payload */
		coap_res_ptr->payload_len = sizeof(relay_state);
		coap_res_ptr->payload_ptr = &relay_state;
		/* Then call sn_nsdl_send_coap_message() - function to build and send CoAP response to NSP */
		sn_nsdl_send_coap_message(address, coap_res_ptr);
	}

	/* If PUT to resource received */
	else if (received_coap_ptr->msg_code == COAP_MSG_CODE_REQUEST_PUT)
	{
		/* Check if there is payload */
		if (received_coap_ptr->payload_ptr && received_coap_ptr->payload_len < 2)
		{
			/* Change relay state */
			relay_state = received_coap_ptr->payload_ptr[0];
		}

		/* Build response "Changed" */
		coap_res_ptr = sn_coap_build_response(received_coap_ptr, COAP_MSG_CODE_RESPONSE_CHANGED);
		if (received_coap_ptr->msg_type == COAP_MSG_TYPE_NON_CONFIRMABLE)
		{
			coap_res_ptr->msg_type = COAP_MSG_TYPE_NON_CONFIRMABLE;
			coap_res_ptr->msg_id = current_mid++;
		}
		/* Build and send response */
		sn_nsdl_send_coap_message(address, coap_res_ptr);
	}
	 /* Method not supported - For delete and post requests */
	else
	{
		printf("Method not supported\n");
		coap_res_ptr = sn_coap_build_response(coap_res_ptr, COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED);
		sn_nsdl_send_coap_message(address, coap_res_ptr);
	}

	/* Now free allocated memory - Only response message must be released. */
	if(coap_res_ptr->token_ptr)
	{
		own_free(coap_res_ptr->token_ptr);
	}
	own_free(coap_res_ptr);

	return 0;
}

/* This is callback for other DYNAMIC resources */
static uint8_t general_resource_cb(sn_coap_hdr_s *received_coap_ptr, sn_nsdl_addr_s *address, sn_proto_info_s * proto)
{
	sn_coap_hdr_s *coap_res_ptr = 0;
	uint8_t i = 0;

	printf("General callback\n");


	if (received_coap_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
	{
		coap_res_ptr = sn_coap_build_response(received_coap_ptr, COAP_MSG_CODE_RESPONSE_CONTENT);
		coap_res_ptr->content_type_ptr = &text_plain;
		coap_res_ptr->content_type_len = sizeof(text_plain);



		/* res bat */
		if(compare_uripaths(received_coap_ptr, res_bat))
		{
			coap_res_ptr->options_list_ptr = own_alloc(sizeof(sn_coap_options_list_s));
			if(!coap_res_ptr->options_list_ptr)
				sn_coap_parser_release_allocated_coap_msg_mem(coap_res_ptr);

			memset(coap_res_ptr->options_list_ptr, 0, sizeof(sn_coap_options_list_s));
			coap_res_ptr->options_list_ptr->observe_len = 1;
			coap_res_ptr->options_list_ptr->observe_ptr = &obs_number;

			obs_number ++;

			coap_res_ptr->payload_len = sizeof(res_bat_val);
			coap_res_ptr->payload_ptr = res_bat_val;

			if(received_coap_ptr->options_list_ptr)
			{
				if(received_coap_ptr->options_list_ptr->observe)
					printf("Observe\n");
			}
			if(received_coap_ptr->token_ptr)
			{
				printf("token:");
				while(i < received_coap_ptr->token_len)
				{
					printf("%x:", *(received_coap_ptr->token_ptr + i));
					i++;
				}
				printf("\n");
				memset(obs_token, 0, 8);
				memcpy(obs_token, received_coap_ptr->token_ptr, received_coap_ptr->token_len);
				obs_token_len = received_coap_ptr->token_len;
			}
		}

		/* res pwr */
		else if(compare_uripaths(received_coap_ptr, res_pwr))
		{
			i = 0;
			coap_res_ptr->options_list_ptr = own_alloc(sizeof(sn_coap_options_list_s));
			if(!coap_res_ptr->options_list_ptr)
				sn_coap_parser_release_allocated_coap_msg_mem(coap_res_ptr);

			memset(coap_res_ptr->options_list_ptr, 0, sizeof(sn_coap_options_list_s));

			coap_res_ptr->options_list_ptr->max_age_ptr = &i;
			coap_res_ptr->options_list_ptr->max_age_len = 1;

			if(relay_state == '1')
			{
				coap_res_ptr->payload_len = sizeof(res_pwr_val)-1;
				coap_res_ptr->payload_ptr = res_pwr_val;
			}
			else if(relay_state == '0')
			{
				coap_res_ptr->payload_len = sizeof(res_pwr_val_off)-1;
				coap_res_ptr->payload_ptr = res_pwr_val_off;
			}
		}

		/* res temp */
		/* This makes delayed response, first ack and after that real value */
		else if(compare_uripaths(received_coap_ptr, res_temp))
		{
			send_ack(received_coap_ptr, address);
			if(coap_res_ptr->token_ptr)
			{
				own_free(coap_res_ptr->token_ptr);
			}

			if(coap_res_ptr->options_list_ptr)
				own_free(coap_res_ptr->options_list_ptr);
			own_free(coap_res_ptr);

			return 0;
		}
		sn_nsdl_send_coap_message(address, coap_res_ptr);

	}
	 /* Method not supported */
	else
	{
		printf("Method not supported\n");
		coap_res_ptr = sn_coap_build_response(received_coap_ptr, COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED);
		sn_nsdl_send_coap_message(address, coap_res_ptr);
	}

	if(coap_res_ptr->token_ptr)
	{
		own_free(coap_res_ptr->token_ptr);
	}

	if(coap_res_ptr->options_list_ptr)
		own_free(coap_res_ptr->options_list_ptr);
	own_free(coap_res_ptr);

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

void send_ack(sn_coap_hdr_s *received_coap_ptr, sn_nsdl_addr_s *address)
{
	sn_coap_hdr_s *coap_res_ptr = 0;
	uint16_t message_len = 0;
	uint8_t *message_ptr;

	if (received_coap_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
	{
		if (received_coap_ptr->msg_type == COAP_MSG_TYPE_CONFIRMABLE)
		{
			coap_res_ptr = own_alloc(sizeof(sn_coap_hdr_s));
			if(!coap_res_ptr)
				return;
			memset(coap_res_ptr, 0x00, sizeof(sn_coap_hdr_s));

			coap_res_ptr->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
			coap_res_ptr->msg_code = COAP_MSG_CODE_EMPTY;
			coap_res_ptr->msg_id = received_coap_ptr->msg_id;

			delayed_msg_type = COAP_MSG_TYPE_CONFIRMABLE;
		}
		else
		{
			delayed_msg_type = COAP_MSG_TYPE_NON_CONFIRMABLE;
		}


		if(received_coap_ptr->token_len)
		{
			memset(delayed_token, 0, 8);
			delayed_token_len = received_coap_ptr->token_len;
			memcpy(delayed_token, received_coap_ptr->token_ptr, received_coap_ptr->token_len);
		}

		delayed_response_cnt = 4;
	}


	if(coap_res_ptr)
	{
		message_len = sn_coap_builder_calc_needed_packet_data_size(coap_res_ptr);
		message_ptr = own_alloc(message_len);
		if(!message_ptr)
			return;

		sn_coap_builder(message_ptr, coap_res_ptr);

		tx_function(SN_NSDL_PROTOCOL_COAP, message_ptr, message_len, &received_packet_address);

		/* Free memory */
		if(coap_res_ptr)
		{
			own_free(coap_res_ptr);
		}
		own_free(message_ptr);
	}

	return;
}

/* eDTLS helper functions */

void *ns_dyn_mem_alloc(uint16_t alloc_size)
{

	void *ptr = own_alloc(alloc_size);
	return ptr;
}

void *ns_dyn_mem_temporary_alloc(uint16_t alloc_size)
{
	void *ptr = own_alloc(alloc_size);
	return ptr;
}

void *edtls_malloc(uint16_t alloc_size)
{
	void *ptr = own_alloc(alloc_size);
	return ptr;
}

int8_t randLIB_get_n_bytes_random(uint8_t *data_ptr, uint8_t eight_bit_boundary)
{
	uint8_t i = 0;

	while(i < eight_bit_boundary)
	{
		*(data_ptr + i) = rand();
		i++;
	}
	return 0;
}


void ns_dyn_mem_free(void *ptr)
{
	own_free(ptr);
}

void edtls_free(void *ptr)
{
	own_free(ptr);
}

/* eDTLS sending function */
uint8_t edtls_tx(uint8_t *data_ptr, uint16_t data_len, sn_edtls_address_t *dst_addr)
{
	sa_dst.sin_family = AF_INET;
	sa_dst.sin_port = htons(dst_addr->port);
	memcpy(&sa_dst.sin_addr, dst_addr->address, 4);

	printf("eDTLS TX [%d B]\n", data_len);

	/* Send the message */
	if (sendto(sock_server, data_ptr, data_len, 0, (const struct sockaddr *)&sa_dst, slen_sa_dst)==-1)
				stop_pgm("sendto() failed");

	return 1;
}


/* eDTLS registration status function 				*/
/* eDTLS library returns status during registration */
/* EDTLS_CONNECTION_OK = 1							*/
/* EDTLS_CONNECTION_CLOSED = 2 						*/
/* EDTLS_CONNECTION_FAILED = 3						*/
/* EDTLS_ECC_CALCULATING = 4 (not used in PSK mode) */
void edtls_registration_status(uint8_t status, int16_t session_id)
{
	edtls_connection_status = status;
}

void copy_code(uint8_t * ptr, uint8_t * code_ptr, uint16_t len)
{
	memcpy(ptr, code_ptr, len);
}

uint8_t compare_code(uint8_t * ptr,  unsigned char const * code_ptr, uint8_t len)
{
	return memcmp(ptr, code_ptr, len);
}

static int16_t do_edtls_handshake(sn_edtls_address_t *edtls_address)
{
	/* Start eDTLS connection */
	/* Returns edtls session id. */

	int16_t session_id;
	sn_edtls_data_buffer_t temp_buffer;

	session_id = sn_edtls_connect(edtls_address, &edtls_tx, &edtls_registration_status);

	if(session_id == EDTLS_FAILURE)
	{
		printf("eDTLS session start failed!\n");
		return 0;
	}

	printf("Waiting for eDTLS to connect..\n");

	/* Wait for the eDTLS to connect */
	/* Push all packets to sn_edtls_parse_data - function until edtls_connection_status == EDTLS_CONNECTION_OK */
	/* eDTLS library calls  */
	/* This is just example - using proper state machine is better way to do this */
	while((edtls_connection_status == EDTLS_ECC_CALCULATING))
	{
		if(rcv_size)
		{
			temp_buffer.buff = (uint8_t*)buf;
			temp_buffer.len = rcv_size;
			sn_edtls_parse_data(session_id, &temp_buffer);
			memset(buf, 0, BUFLEN);
			rcv_size = 0;
		}
		sn_edtls_exec(ns_system_time);
	}

	/* If connection failed, then return */
	if(edtls_connection_status == EDTLS_CONNECTION_CLOSED || edtls_connection_status == EDTLS_CONNECTION_FAILED)
	{
		printf("eDTLS connection failed!\n");
		return 0;
	}
	rcv_size = 0;
	printf("eDTLS connected!\n");
	return session_id;
}

void oma_status(sn_nsdl_oma_server_info_t *server_info_ptr)
{
	/* Set eDTLS socket address - same as NSP address in this case */
	memset(edtls_server_address.address, 0, 16);
	edtls_server_address.port = server_info_ptr->omalw_address_ptr->port;
	memcpy(edtls_server_address.address, server_info_ptr->omalw_address_ptr->addr_ptr, server_info_ptr->omalw_address_ptr->addr_len);

	oma = 1;
}
#endif
