/*
 * Copyright Sensinode Ltd 2012
 * main.c
 *
 * 	This is an example application for using NanoStack 2.0 library model.
 *
 *  Short description:
 *
 *
 *  Created on: 17.8.2012
 *  Author: Sensinode/JP
 */
#include <stdlib.h>
#include <stdio.h>

#include "socket_api.h"
#include "net.h"
#include "system_event.h"
#include "string.h"

#include "sn_nsdl.h"
#include "sn_coap_header.h"
#include "sn_coap_protocol.h"

#ifdef USE_EDTLS
	#include "shalib.h"
	#include "sn_edtls_lib.h"
#endif

/*Function prototypes*/
void main_initialize(void);
void main_receive(void * cb);
void tasklet_protocol(event_t *event);
void app_parse_network_event(uint8_t event);

void svr_send_msg(sn_coap_hdr_s *coap_hdr_ptr);
static void svr_msg_handler(uint8_t *msg, int16_t len);
void svr_handle_request(sn_coap_hdr_s *coap_packet_ptr);
void svr_handle_request_mfg(sn_coap_hdr_s *coap_packet_ptr);
void svr_handle_request_mdl(sn_coap_hdr_s *coap_packet_ptr);
void svr_handle_request_bat(sn_coap_hdr_s *coap_packet_ptr);
void svr_handle_request_pwr(sn_coap_hdr_s *coap_packet_ptr);
void svr_handle_request_rel(sn_coap_hdr_s *coap_packet_ptr);
void svr_handle_request_temp(sn_coap_hdr_s *coap_packet_ptr);
void svr_handle_request_wellknown(sn_coap_hdr_s *coap_packet_ptr);
int nsp_register(registration_info_t *endpoint_info_ptr);
int nsp_deregister(uint8_t *location, uint8_t length);

/* These alloc and free functions are required for libCoap */
void *own_alloc(uint16_t size);
void own_free(void *ptr);
uint8_t tx_function(sn_nsdl_capab_e protocol, uint8_t *data_ptr, uint16_t data_len, sn_nsdl_addr_s *address_ptr);
static int8_t main_compare_uripaths(sn_coap_hdr_s *coap_header, const uint8_t *uri_path_to_compare);

/*INPUT INDEX MAX*/
#define INPUT_INDEX_MAX 60
/*RX buffer size*/
#define APP_SOCK_RX_SIZE 1284
#define APP_SOCK_RX_LIMIT (APP_SOCK_RX_SIZE - 4)

#ifdef MSP430
//LED definitions. Note that LEDs are initialized by NanoStack library already so we need just to define ON/OFF/TOGGLE switches to use them.
#define LED1_OFF()		{P4OUT |= 0x01;}
#define LED1_ON()		{P4OUT &= ~0x01;}
#define LED2_OFF()		{P4OUT |= 0x02;}
#define LED2_ON()		{P4OUT &= ~0x02;}
#define LED3_OFF()		{P4OUT |= 0x04;}
#define LED3_ON()		{P4OUT &= ~0x04;}
#define LED4_OFF()		{P4OUT |= 0x08;}
#define LED4_ON()		{P4OUT &= ~0x08;}
#define LED1_TOGGLE()	{P4OUT ^= 0x01;}
#define LED2_TOGGLE()	{P4OUT ^= 0x02;}
#define LED3_TOGGLE()	{P4OUT ^= 0x04;}
#define LED4_TOGGLE()	{P4OUT ^= 0x08;}
#else
#define LED1_OFF()
#define LED1_ON()
#define LED2_OFF()
#define LED2_ON()
#define LED3_OFF()
#define LED3_ON()
#define LED4_OFF()
#define LED4_ON()
#define LED1_TOGGLE()
#define LED2_TOGGLE()
#define LED3_TOGGLE()
#define LED4_TOGGLE()
#endif



static uint8_t RES_MFG[] = {"dev/mfg"};
static uint8_t RES_MFG_VAL[] = {"Sensinode"};
static uint8_t RES_MDL[] = {"dev/mdl"};
static uint8_t RES_MDL_VAL[] = {"NSDL-C power node"};
static uint8_t RES_BAT[] = {"dev/bat"};
static uint8_t RES_BAT_VAL[] = {"3.31"};
static uint8_t RES_PWR[] = {"pwr/0/w"};
static uint8_t RES_PWR_VAL[] = {"80"};
static uint8_t RES_PWR_VAL_OFF[] = {"0"};
static uint8_t RES_REL[] = {"pwr/0/rel"};
static uint8_t RES_TEMP[] = {"sen/temp"};
static uint8_t RES_TEMP_VAL[] = {"25.4"};



#define RES_WELL_KNOWN (const uint8_t *)(".well-known/core")

static uint8_t EP[] = {"nsdlc-power"};
#define EP_LEN 11
static uint8_t EP_TYPE[] = {"PowerNode"};
#define EP_TYPE_LEN 9
static uint8_t LINKS[] = {"</dev/mfg>;rt=ipso:dev-mfg;ct=\"0\",</dev/mdl>;rt=ipso:dev-mdl;ct=\"0\",</dev/bat>;rt=ipso:dev-bat;ct=\"0\",</pwr/0/w>;rt=ipso:pwr-w;ct=\"0\",</pwr/0/rel>;rt=ipso:pwr-rel;ct=\"0\",</sen/temp>;rt=ucum:Cel;ct=\"0\""};
#define LINKS_LEN 200
#define RD_PATH (const uint8_t *)("rd")

/*Global variables*/
static PL_LARGE uint8_t access_point_status = 0;		/* Variable where this application keep connection status of an access point: 0 = No Connection, 1 = Connection established */
static PL_LARGE uint8_t rx_buffer[APP_SOCK_RX_SIZE];	/* Application socket payload buffer used for RX and TX case */
static PL_LARGE ns_address_t node_euid64;
static PL_LARGE uint8_t app_version_info[6];
static PL_LARGE ns_address_t app_src;					/* Used for Receive Data source Address store*/
static PL_LARGE ns_address_t app_dest;					/* Used for Socket Send Destination Address*/
static PL_LARGE ns_address_t access_point_adr;			/* Access Point Address store space */
static PL_LARGE ns_address_t primary_parent_address;
static PL_LARGE int8_t app_udp_socket = -1;				/*UDP socket variable*/
static PL_LARGE uint16_t udp_socket = 61630;	/* Listened port (default 61630) */

/* CoAP related globals*/
uint16_t current_mid = 0;
uint8_t	 text_plain = COAP_CT_TEXT_PLAIN;
uint8_t	 link_format = COAP_CT_LINK_FORMAT;

/* Resource related globals*/
uint8_t res_rel = '1';
uint8_t *reg_location;
int8_t reg_location_len;

/* eDTLS related glogals */
#ifdef USE_EDTLS
uint8_t edtls_session_status = 0;
uint8_t edtls_session_id;
sn_edtls_address_t edtls_address;
sn_edtls_data_buffer_t edtls_message_buffer;
#endif

#ifdef MSP430
__root const uint8_t hard_mac[8] @ 0x21000 = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF}; //0xfd80 = {0x04, 0x02, 0x00, 0xde, 0xad, 0x00, 0x00, 0x01};  // need if hardware debugger is used
#endif

#ifdef USE_EDTLS
static uint8_t nsp_addr[] = {0x20, 0x01, 0x04, 0x70, 0x1F, 0x15, 0x16, 0xEA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0xdc};
#else
static uint8_t nsp_addr[] = {0x20, 0x01, 0x04, 0x70, 0x1F, 0x15, 0x16, 0xEA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0xde};
#endif
static uint16_t nsp_port = 5683;

/*Configurable channel list for beacon scan*/
static PL_LARGE uint32_t channel_list = 0x07FFF800;

uint8_t net_security_key[16] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};
static PL_LARGE net_security_t level = (net_security_t) NW_SECURITY_LEVEL_MIC128;

//all timer IDs are introduced below
#define START 0xf1
#define BUTTON_TIMER 0xf2
#define NETWORK_CONNECT_TIMER 0xf6
#define REG_TIMER 0xf3


static uint8_t received_address[16];
static uint16_t received_port = 0;
static uint8_t start_msg = 0;

static int8_t rssi = 0;


/*
* A callback that will be called always when NS has nothing to do. CPU could be set to idle here but beaware, interrupts needs to be enabled and proper exits out of lpm modes depends of platforms.
*/
uint32_t app_ns_core_idle(uint8_t event, uint32_t time_ns)
{
	uint32_t returned_slept_time = 0;
	if(event == EV_READY_TO_SLEEP)
	{
		
	}
	else
	{
		//Set Idle
	}
	return returned_slept_time;
}

/*
 * \brief Main should call two internal initializers of NanoStack.
 * -net_init_core(idle callback) to initialize NanoStack library.
 * -event_dispatch() to enter the NanoStack OS (contain a while loop and code never exited).
 */
void main(void)
{	
#ifdef CC2530
	hal_init(0);
#endif
    net_init_core(app_ns_core_idle);
	event_dispatch();
}



/*
 * \brief This function initializes socket, get version of library, sets all in good shape.
 */
static void main_initialize_NanoStack_library_API(void)
{
	/*Set Link layer channel list. Set all 16 channels default*/
	net_value_set(NW_SCAN_CHANNEL_LIST, channel_list);

	//Get version info
	net_get_version_information(app_version_info);
	net_address_get(ADDR_MAC64,&node_euid64);

	/*Open UDP and ICMP sockets at start-up*/
	app_udp_socket = socket_open(SOCKET_UDP, udp_socket, main_receive);

}



/*
 * \brief This function is used to poll the access point connectivity.
 *  The flag 'access_point_status' is used to indicate if AP connection is established.
 *  If the connection is established, the poll timer NETWORK_CONNECT_TIMER is disabled.
 *  If the connection is not established or becomes invalid, the poll timer NETWORK_CONNECT_TIMER is enabled.
 *  When this timer is active, LEDa & LEDb is toggled.
 */
static void main_poll_access_point_status(void)
{
    timer_sys_event_cancel((uint8_t)NETWORK_CONNECT_TIMER);
	
	

	if(!access_point_status)
	{
    	timer_sys_event((uint8_t)NETWORK_CONNECT_TIMER, 500);
	}
	else
	{
	    LED1_OFF();
        LED2_OFF();
        LED4_OFF();
        LED3_ON();
		
	}
}




/*
 * \brief This function tries to enable networking. Networking is enabled using net_start()
 * In case if the network starts successfully:
 * -Start NETWORK_CONNECT_TIMER
 *
 * In case if the network start fails:
 * -Start START timer which ensures that netstart is to be called every 1 second.
 *
 */
static void main_try_to_enable_networking(void)
{
	/*Start Stack in router mode without security and use long addresses*/
    	timer_sys_event_cancel((uint8_t)NETWORK_CONNECT_TIMER);
    	
        //If I ever wanted to use link layer security, I would decomment below two lines. Note also all related variables and arrays.
        //net_security_set(&net_security_key[0], level);
    	//if(net_start(NW_INFRA_ROUTER, (NW_SECURITY_ON | NW_SHORT_ADDRESS_ALLOCATE_OFF)) != 0)
	        if(net_start(NW_INFRA_ROUTER, (NW_SECURITY_OFF | NW_SHORT_ADDRESS_ALLOCATE_OFF)) != 0)
		{
			
            //It is a good practise to always cancel a timer to be launched as it might be already running with same ID.
			timer_sys_event_cancel(START);
			timer_sys_event((uint8_t)START, 1000);
		}
		else
        {
            timer_sys_event_cancel((uint8_t)NETWORK_CONNECT_TIMER);
			timer_sys_event((uint8_t)NETWORK_CONNECT_TIMER, 500);
        }
}


/*
 * \brief A function which will be eventually called by NanoStack OS when ever the OS has an event to deliver.
 * @param event, describes the sender, receiver and event type.
 *
 * NOTE: Interrupts requested by HW are possible during this function!
 */
void tasklet_main(event_t *event)
{
	
	
	switch(event->sender)
	{
		//This event is delivered every and each time when there is an event or some data in socket queues.
		case EV_SOCKET:
			/* Socket Event Handler */
			//Obsolete case and not used here.
			break;

		//This event is delivered every and each time when there is new information of network connectivity.
		case EV_NETWORK:
			/* Network Event state event handler */
			app_parse_network_event(event->event);
			break;

		case SYSTEM:
			/*Event with type EV_INIT is an initializer event of NanoStack OS.
			 * The event is delivered when the NanoStack OS is running fine. This event should be delivered ONLY ONCE.
			 */
			if (event->event == EV_INIT)
			{	
                LED1_ON();
				//call NanoStack OS initializer to accept application EV_INIT.
				main_initialize();	
                  	      app_dest.identifier = 0;
							

				main_initialize_NanoStack_library_API();	


				sn_coap_builder_and_parser_init(&own_alloc, &own_free);
				sn_coap_protocol_init(&own_alloc, &own_free, &tx_function);
#ifdef USE_EDTLS
				sn_edtls_libraray_initialize();
#endif
				timer_sys_event_cancel(START);
				timer_sys_event(START, 1000);
			}					
		break;
		case SYSTEM_TIMER:
			//its a good practise to always cancel a pending timer with same ID, just for robust behavior of NanoStack OS.
			timer_sys_event_cancel(event->event);
			switch(event->event)
			{
				case START:
					//lets try to enable the networking support.
                    LED2_TOGGLE();
					main_try_to_enable_networking();
					/*
					 * Next things that may take place are:
					 * -In case of error, this timer event is delivered again
					 * -In case of successful net_start(), the next this should be case
					 * NET_READY in function app_parse_network_event().					
					 */
				break;
																		   		  
				case NETWORK_CONNECT_TIMER:		
                    LED4_TOGGLE();
					main_poll_access_point_status();		
				break;	
				
				case REG_TIMER:
					/* All registrations are hadled here */
					registration_info_t endpoint_info;
					timer_sys_event_cancel((uint8_t)REG_TIMER);
#ifdef USE_EDTLS
					if(edtls_session_status != EDTLS_CONNECTION_OK)
					{
						LED4_TOGGLE();
						timer_sys_event((uint8_t)REG_TIMER, 500);
						return;
					}

#endif
					//register to NSP
					endpoint_info.endpoint_ptr = EP;
					endpoint_info.endpoint_len = EP_LEN;
					endpoint_info.endpoint_type_ptr = EP_TYPE;
					endpoint_info.endpoint_type_len = EP_TYPE_LEN;
					endpoint_info.links_ptr = LINKS;
					endpoint_info.links_len = LINKS_LEN;

					nsp_register(&endpoint_info);



				break;
				
			}	
		break;
		/*Application specific event*/
		case APP_SPESIFIC_EVENT:
			switch(event->event)
			{
			
				default:
					break;
			}
			break;
		default:
		break;
	}
}

/**
  * Network state event handler.
  * \param event show network start response or current network state.
  *
  */
void app_parse_network_event(uint8_t event)
{
	switch (event)
	{
		//In this case, a node has established a connection to the access point. Further measures should be taken by application.
		case NET_READY:
		if(access_point_status==0)
		{


            LED1_ON();
            LED2_ON();
            LED3_ON();
            LED4_ON();
            LED1_OFF();
            LED2_OFF();
            LED4_OFF();
                      
			//mark access point status to TRUE
			access_point_status=1;	
#ifndef USE_NSP_ADDRESS
            net_address_get(ADDR_ND_ER_IPV6,&access_point_adr);
            memcpy(&nsp_addr, &access_point_adr.address, 16);
#endif

#ifdef USE_EDTLS
			edtls_address.port = nsp_port;
			edtls_address.socket = app_udp_socket;
			memcpy(edtls_address.address, nsp_addr, 16);

			edtls_session_id = sn_edtls_connect(&edtls_address);
#endif

			timer_sys_event((uint8_t)REG_TIMER, 1000);

					
		}
		break;
		case NET_NO_BEACON:
			/* Link Layer Active Scan Fail, Stack is Already at Idle state */
			access_point_status=0;

		break;
		case NET_NO_ND_ROUTER:
			/* No ND Router at current Channel Stack is Already at Idle state */
			access_point_status=0;

		break;
		case NET_BORDER_ROUTER_LOST:
			 /*Connection to Access point is lost wait for Scan Result */
            access_point_status=0;
		break;
		default:
		break;
	}
	/*If Connection is failed, restart scan*/
	if(access_point_status==0)
	{
        LED1_OFF();
        LED2_OFF();
        LED3_OFF();
        LED4_OFF();
        timer_sys_event_cancel(START);
		timer_sys_event(START, 1000);		
		start_msg = 0;
	}
}


/**
  * Socket event handler.
  * \param event include socket ID and Socket Event Type. 4 MSB indicate event type and 4 LSB is for socket ID
  *
  */
void main_receive(void *cb)
{
	socket_callback_t * cb_res =0;
	int16_t length;
	cb_res = (socket_callback_t *) cb;
    LED2_ON();
	if(cb_res->event_type == SOCKET_DATA)
	{
		if(1)
		{
			//Read data to the RX buffer
			length = socket_read(cb_res->socket_id, &app_src, rx_buffer, APP_SOCK_RX_SIZE);  //replace rx_buffer payload

				if(length)
				{
					if(cb_res->socket_id == app_udp_socket)
					{
						// Handles data received in UDP socket
						memcpy(app_dest.address,app_src.address,16);
						app_dest.identifier = app_src.identifier;

#ifdef USE_EDTLS
						edtls_message_buffer.buff = rx_buffer;
						edtls_message_buffer.len = (uint16_t)length;
						edtls_message_buffer.address = 0;
						if(sn_edtls_read_data(edtls_session_id, &edtls_message_buffer) != -1)
							svr_msg_handler(edtls_message_buffer.buff, edtls_message_buffer.len);
#else
						// parse data
						svr_msg_handler(rx_buffer, length);
#endif
					}
					 // Clear rx_buffer in order to avoid misunderstandings
					memset(rx_buffer,0,128);
			}	
		}
	}
    LED2_OFF();
}


/**************************************************/
void svr_send_msg(sn_coap_hdr_s *coap_hdr_ptr)
{
	uint8_t 	*message_ptr = NULL;
	uint16_t 	message_len	= 0;

	/* Calculate message length */
	message_len = sn_coap_builder_calc_needed_packet_data_size(coap_hdr_ptr);

	/* Allocate memory for message and check was allocating successfully */
	message_ptr = malloc(message_len);
	if(!message_ptr)
		return;

	/* Build CoAP message */
	sn_coap_builder(message_ptr, coap_hdr_ptr);

	memcpy(app_dest.address, nsp_addr, 16);
	app_dest.identifier = nsp_port;
	app_dest.type = ADDRESS_IPV6;

	/* Send the message */
#ifdef eDTLS
	edtls_message_buffer.buff = data_ptr;
	edtls_message_buffer.len = datalen;
	edtls_message_buffer.address = 0;
	sn_edtls_write_data(edtls_session_id, &edtls_message_buffer);
#else
    socket_sendto(app_udp_socket, &app_dest, message_ptr, message_len);
#endif

	free(message_ptr);
	free(coap_hdr_ptr->payload_ptr);
	if(coap_hdr_ptr->options_list_ptr)
	{
		if(coap_hdr_ptr->options_list_ptr->uri_query_ptr)
			free(coap_hdr_ptr->options_list_ptr->uri_query_ptr);
		free(coap_hdr_ptr->options_list_ptr);
	}
	free(coap_hdr_ptr);
}

int nsp_register(registration_info_t *endpoint_info_ptr)
{
	/* Build CoAP request */

	sn_coap_hdr_s *coap_hdr_ptr;
	coap_hdr_ptr = malloc(sizeof(sn_coap_hdr_s));
	if(!coap_hdr_ptr)
		return -1;
	memset(coap_hdr_ptr, 0x00, sizeof(sn_coap_hdr_s));

	/* Build the registration CoAP request using the libCoap helper function */
	sn_coap_register(coap_hdr_ptr, endpoint_info_ptr);
	svr_send_msg(coap_hdr_ptr);

	return 0;
}

int nsp_deregister(uint8_t *location, uint8_t length)
{

	/* Build CoAP request */
	sn_coap_hdr_s *coap_hdr_ptr;
	coap_hdr_ptr = malloc(sizeof(sn_coap_hdr_s));
	if(!coap_hdr_ptr)
		return -1;
	memset(coap_hdr_ptr, 0x00, sizeof(sn_coap_hdr_s));

	/* Build the de-registration CoAP request using the libCoap helper function */
	sn_coap_deregister(coap_hdr_ptr, location, length);
	svr_send_msg(coap_hdr_ptr);

	return 0;
}

void svr_msg_handler(uint8_t *msg, int16_t len)
{

	sn_coap_hdr_s 	*coap_packet_ptr 	= NULL;
	coap_version_e coap_version = COAP_VERSION_1;

	/* Parse the buffer into a CoAP message structure */
	coap_packet_ptr = sn_coap_parser(len, msg, &coap_version);

	/* Check if parsing was successfull */
	if(coap_packet_ptr == (sn_coap_hdr_s *)NULL)
	{
		return;
	}

	/* If the message code range is a request method, then handle the request */
	if (coap_packet_ptr->msg_code >= 1 && coap_packet_ptr->msg_code <= 4)
	{
		svr_handle_request(coap_packet_ptr);
	}

	else if(coap_packet_ptr->msg_code == COAP_MSG_CODE_RESPONSE_CREATED)
	{
		LED4_ON();
		if (coap_packet_ptr->options_list_ptr && coap_packet_ptr->options_list_ptr->location_path_ptr)
				{
					reg_location_len = coap_packet_ptr->options_list_ptr->location_path_len;
					reg_location = own_alloc(coap_packet_ptr->options_list_ptr->location_path_len);
					if (reg_location)
						memcpy(reg_location, (char *)coap_packet_ptr->options_list_ptr->location_path_ptr, reg_location_len);
					else
					{
						sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
						return;
					}
				}
	}

	sn_coap_parser_release_allocated_coap_msg_mem(coap_packet_ptr);
}


void svr_handle_request(sn_coap_hdr_s *coap_packet_ptr)
{
	/* Compare the request URI against server's resource, pass to resource handler when matching */
	if(main_compare_uripaths(coap_packet_ptr, RES_MFG))
		svr_handle_request_mfg(coap_packet_ptr);
	else if (main_compare_uripaths(coap_packet_ptr, RES_MDL))
		svr_handle_request_mdl(coap_packet_ptr);
	else if (main_compare_uripaths(coap_packet_ptr, RES_BAT))
		svr_handle_request_bat(coap_packet_ptr);
	else if (main_compare_uripaths(coap_packet_ptr, RES_PWR))
		svr_handle_request_pwr(coap_packet_ptr);
	else if (main_compare_uripaths(coap_packet_ptr, RES_REL))
		svr_handle_request_rel(coap_packet_ptr);
	else if (main_compare_uripaths(coap_packet_ptr, RES_TEMP))
		svr_handle_request_temp(coap_packet_ptr);
	else if (main_compare_uripaths(coap_packet_ptr, RES_WELL_KNOWN))
		svr_handle_request_wellknown(coap_packet_ptr);
	/* URI not found */
	else
	{
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
		coap_res_ptr->payload_len = (sizeof(RES_MFG_VAL)-1);
		coap_res_ptr->payload_ptr = malloc(coap_res_ptr->payload_len);
		if(!coap_res_ptr->payload_ptr)
			return;
		memcpy(coap_res_ptr->payload_ptr, RES_MFG_VAL, coap_res_ptr->payload_len);
		svr_send_msg(coap_res_ptr);
		return;
	}
	 /* Method not supported */
	else
	{
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
		coap_res_ptr->payload_len = (sizeof(RES_MDL_VAL)-1);
		coap_res_ptr->payload_ptr = malloc(coap_res_ptr->payload_len);
		if(!coap_res_ptr->payload_ptr)
			return;
		memcpy(coap_res_ptr->payload_ptr, RES_MDL_VAL, coap_res_ptr->payload_len);
		svr_send_msg(coap_res_ptr);
		return;
	}
	/* Method not supported */
	else
	{
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
		coap_res_ptr->payload_len = (sizeof(RES_BAT_VAL)-1);
		coap_res_ptr->payload_ptr = malloc(coap_res_ptr->payload_len);
		if(!coap_res_ptr->payload_ptr)
			return;
		memcpy(coap_res_ptr->payload_ptr, RES_BAT_VAL, coap_res_ptr->payload_len);
		svr_send_msg(coap_res_ptr);
		return;
	}
	 /* Method not supported */
	else
	{
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
			coap_res_ptr->payload_len = (sizeof(RES_PWR_VAL)-1);
			coap_res_ptr->payload_ptr = malloc(coap_res_ptr->payload_len);
			if(!coap_res_ptr->payload_ptr)
				return;
			memcpy(coap_res_ptr->payload_ptr, RES_PWR_VAL, coap_res_ptr->payload_len);
		} else {
			coap_res_ptr->payload_len = (sizeof(RES_PWR_VAL_OFF)-1);
			coap_res_ptr->payload_ptr = malloc(coap_res_ptr->payload_len);
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
		coap_res_ptr->payload_ptr = malloc(coap_res_ptr->payload_len);
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
		coap_res_ptr->payload_len = (sizeof(RES_TEMP_VAL)-1);
		coap_res_ptr->payload_ptr = malloc(coap_res_ptr->payload_len);
		if(!coap_res_ptr->payload_ptr)
			return;
		memcpy(coap_res_ptr->payload_ptr, RES_TEMP_VAL, coap_res_ptr->payload_len);
		svr_send_msg(coap_res_ptr);
		return;
	}
	 /* Method not supported */
	else
	{
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED);
		svr_send_msg(coap_res_ptr);
	}
}


void svr_handle_request_wellknown(sn_coap_hdr_s *coap_packet_ptr)
{
	sn_coap_hdr_s *coap_res_ptr;
	if (coap_packet_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
	{
		coap_res_ptr = sn_coap_build_response(coap_packet_ptr, COAP_MSG_CODE_RESPONSE_CONTENT);
		coap_res_ptr->content_type_ptr = &link_format;
		coap_res_ptr->content_type_len = sizeof(link_format);
		coap_res_ptr->payload_len = LINKS_LEN;
		coap_res_ptr->payload_ptr = malloc(coap_res_ptr->payload_len);
		if(!coap_res_ptr->payload_ptr)
			return;
		memcpy(coap_res_ptr->payload_ptr, LINKS, coap_res_ptr->payload_len);
		svr_send_msg(coap_res_ptr);
		return;
	}
	 /* Method not supported */
	else
	{
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


static int8_t main_compare_uripaths(sn_coap_hdr_s *coap_header, const uint8_t *uri_path_to_compare)
{
    if(memcmp(coap_header->uri_path_ptr,&uri_path_to_compare[0], coap_header->uri_path_len) == 0)
	{
		return 1;
	}
	return 0;
}

#ifdef USE_EDTLS
void 	*edtls_malloc(uint16_t size)
{
	return own_alloc(size);
}

void 	edtls_free(void *ptr)
{
	own_free(ptr);
}

uint8_t 	edtls_tx(uint8_t *message_ptr, uint16_t message_len, sn_edtls_address_t *address_ptr)
{
	memcpy(app_dest.address, address_ptr->address, 16);
	app_dest.identifier = address_ptr->port;
	app_dest.type = ADDRESS_IPV6;

    socket_sendto(address_ptr->socket, &app_dest, message_ptr, message_len);
}

uint8_t 	edtls_random()
{
	return 1;
}

void 	edtls_registration_status(uint8_t received_status)
{
	edtls_session_status = received_status;
}

#endif



