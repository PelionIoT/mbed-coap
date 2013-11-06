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
#include "sn_nsdl_lib.h"

#include "resource_generation_help.h"

/*Function prototypes*/
void main_initialize(void);
void main_receive(void * cb);
void tasklet_protocol(event_t *event);
void app_parse_network_event(uint8_t event);

/* These alloc and free functions are required for libCoap */
void *own_alloc(uint16_t size);
void own_free(void *ptr);
uint8_t tx_function(sn_nsdl_capab_e protocol, uint8_t *data_ptr, uint16_t data_len, sn_nsdl_addr_s *address_ptr);
uint8_t rx_function(sn_coap_hdr_s *coap_header, sn_nsdl_addr_s *address_ptr);
static uint8_t relay_resource_cb(sn_coap_hdr_s *coap_ptr, sn_nsdl_addr_s *address, sn_proto_info_s * proto);
static uint8_t general_resource_cb(sn_coap_hdr_s *coap_ptr, sn_nsdl_addr_s *address, sn_proto_info_s * proto);
static int8_t compare_uripaths(sn_coap_hdr_s *coap_header, const uint8_t *uri_path_to_compare);

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


static PL_LARGE uint8_t res_mgf[] = {"dev/mfg"};
static PL_LARGE uint8_t res_mgf_val[] = {"Sensinode"};
static PL_LARGE uint8_t res_mdl[] = {"dev/mdl"};
static PL_LARGE uint8_t res_mdl_val[] = {"NSDL-C light node"};
static PL_LARGE uint8_t res_bat[] = {"dev/bat"};
static PL_LARGE uint8_t res_bat_val[] = {"3.31"};
static PL_LARGE uint8_t res_pwr[] = {"pwr/0/w"};
static PL_LARGE uint8_t res_pwr_val[] = {"80"};
static PL_LARGE uint8_t res_pwr_val_off[] = {"0"};
static PL_LARGE uint8_t res_rel[] = {"pwr/0/rel"};
static PL_LARGE uint8_t res_temp[] = {"sen/temp"};
static PL_LARGE uint8_t res_temp_val[] = {"25.4"};
static PL_LARGE uint8_t res_gps[] = {"gps/loc"};
static PL_LARGE uint8_t res_gps_val[] = {"65.017935,25.443785"};
static PL_LARGE uint8_t res_type_test[] = {"test"};

static PL_LARGE uint8_t ep[] = {"nsdlc-light"};
static PL_LARGE uint8_t ep_type[] = {"light"};
static PL_LARGE uint8_t lifetime_ptr[] = {"1200"};


/*Global variables*/
static PL_LARGE uint8_t access_point_status = 0;		/* Variable where this application keep connection status of an access point: 0 = No Connection, 1 = Connection established */
//static PL_LARGE uint8_t rx_buffer[APP_SOCK_RX_SIZE];	/* Application socket payload buffer used for RX and TX case */
static PL_LARGE ns_address_t node_euid64;
static PL_LARGE uint8_t app_version_info[6];
static PL_LARGE ns_address_t app_src;					/* Used for Receive Data source Address store*/
static PL_LARGE ns_address_t app_dest;					/* Used for Socket Send Destination Address*/
static PL_LARGE ns_address_t access_point_adr;			/* Access Point Address store space */
static PL_LARGE ns_address_t primary_parent_address;
static PL_LARGE int8_t app_udp_socket = -1;				/*UDP socket variable*/
static PL_LARGE uint16_t udp_socket = 61630;			/* Listened port (default 61630) */

/* CoAP related globals*/
uint16_t current_mid = 0;
uint8_t	 text_plain = COAP_CT_TEXT_PLAIN;
uint8_t	 link_format = COAP_CT_LINK_FORMAT;

/* Resource related globals*/
uint8_t res_rel_val = '1';
uint8_t *reg_location;
int8_t reg_location_len;


#ifdef MSP430
__root const uint8_t hard_mac[8] @ 0x21000 = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19}; //0xfd80 = {0x04, 0x02, 0x00, 0xde, 0xad, 0x00, 0x00, 0x01};  // need if hardware debugger is used
#endif
static PL_LARGE uint8_t nsp_addr[] = {0x20, 0x01, 0x04, 0x70, 0x1F, 0x15, 0x16, 0xEA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81, 0x8e};
static uint16_t nsp_port = 5684;

/*Configurable channel list for beacon scan*/
static PL_LARGE uint32_t channel_list = 0x07FFF800;

uint8_t net_security_key[16] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};
//static PL_LARGE net_security_t level = (net_security_t) NW_SECURITY_LEVEL_MIC128;

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
                sn_nsdl_mem_s memory_struct;
                memory_struct.sn_nsdl_alloc = &own_alloc;
                memory_struct.sn_nsdl_free = &own_free;

				LED1_ON();
				//call NanoStack OS initializer to accept application EV_INIT.
				main_initialize();	
                  	      app_dest.identifier = 0;
							

				main_initialize_NanoStack_library_API();	


				sn_coap_builder_and_parser_init(&own_alloc, &own_free);
				sn_coap_protocol_init(&own_alloc, &own_free, &tx_function);
				sn_nsdl_init(&tx_function ,&rx_function, &memory_struct);

                                set_NSP_address(nsp_addr, nsp_port, SN_NSDL_ADDRESS_TYPE_IPV6);
                                
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
					sn_nsdl_ep_parameters_s *endpoint_ptr = 0;
					sn_nsdl_resource_info_s	*resource_ptr = 0;

					/* All registrations are hadled here */
					timer_sys_event_cancel((uint8_t)REG_TIMER);

					//register to NSP
					//..do the tricks with full nsdl
					/* Create resources */

					resource_ptr = own_alloc(sizeof(sn_nsdl_resource_info_s));
					if(!resource_ptr)
						return;

					memset(resource_ptr, 0, sizeof(sn_nsdl_resource_info_s));

					resource_ptr->resource_parameters_ptr = own_alloc(sizeof(sn_nsdl_resource_parameters_s));
					if(!resource_ptr->resource_parameters_ptr)
					{
						own_free(resource_ptr);
						return;
					}
					memset(resource_ptr->resource_parameters_ptr, 0, sizeof(sn_nsdl_resource_parameters_s));
          
					// dev
					CREATE_STATIC_RESOURCE(resource_ptr, sizeof(res_mgf)-1, (uint8_t*) res_mgf, sizeof(res_type_test)-1, (uint8_t*)res_type_test,  (uint8_t*) res_mgf_val, sizeof(res_mgf_val)-1);
					// model
					CREATE_STATIC_RESOURCE(resource_ptr, sizeof(res_mdl)-1, (uint8_t*) res_mdl, sizeof(res_type_test)-1, (uint8_t*)res_type_test,  (uint8_t*) res_mdl_val, sizeof(res_mdl_val)-1);
					// bat
					CREATE_DYNAMIC_RESOURCE(resource_ptr, sizeof(res_bat)-1, (uint8_t*) res_bat, sizeof(res_type_test)-1, (uint8_t*)res_type_test, 0, &general_resource_cb)
					// pwr
					CREATE_DYNAMIC_RESOURCE(resource_ptr, sizeof(res_pwr)-1, (uint8_t*) res_pwr, sizeof(res_type_test)-1, (uint8_t*)res_type_test, 0, &general_resource_cb)
					// rel
					CREATE_DYNAMIC_RESOURCE(resource_ptr, sizeof(res_rel)-1, (uint8_t*) res_rel, sizeof(res_type_test)-1, (uint8_t*)res_type_test, 0, &relay_resource_cb)
					// temp
					CREATE_DYNAMIC_RESOURCE(resource_ptr, sizeof(res_temp)-1, (uint8_t*) res_temp, sizeof(res_type_test)-1, (uint8_t*)res_type_test, 0, &general_resource_cb)
					// gps
					CREATE_DYNAMIC_RESOURCE(resource_ptr, sizeof(res_gps)-1, (uint8_t*) res_gps, sizeof(res_type_test)-1, (uint8_t*)res_type_test, 0, &general_resource_cb)
					/* Register with NSP */

					own_free(resource_ptr->resource_parameters_ptr);
					own_free(resource_ptr);

					INIT_REGISTER_NSDL_ENDPOINT(endpoint_ptr, ep, ep_type, lifetime_ptr);
					sn_nsdl_register_endpoint(endpoint_ptr);
					CLEAN_REGISTER_NSDL_ENDPOINT(endpoint_ptr);

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
	uint8_t *payload = 0;
	sn_nsdl_addr_s src_struct;

	src_struct.addr_len = 16;
	src_struct.addr_ptr = nsp_addr;
	src_struct.socket_information = 0;
	src_struct.type = SN_NSDL_ADDRESS_TYPE_IPV6;
	src_struct.port = nsp_port;

	cb_res = (socket_callback_t *) cb;

    LED2_ON();
	if(cb_res->event_type == SOCKET_DATA)
	{
		if ( cb_res->d_len > 0)
		{
			payload = (uint8_t *) own_alloc(cb_res->d_len);
			if(payload)
			{
				//Read data to the RX buffer
				length = socket_read(cb_res->socket_id, &app_src, payload, cb_res->d_len);

					if(length)
					{
						if(cb_res->socket_id == app_udp_socket)
						{
							// Handles data received in UDP socket
							memcpy(app_dest.address,app_src.address,16);
							app_dest.identifier = app_src.identifier;
							// parse data
							sn_nsdl_process_coap(payload, length, &src_struct);
						}
						 // Clear rx_buffer in order to avoid misunderstandings
						//memset(rx_buffer,0,128);

					}
					own_free(payload);
			}
		}
	}
    LED2_OFF();

#if 0
	socket_callback_t * cb_res =0;
	int16_t length;
	sn_nsdl_addr_s src_struct;

	src_struct.addr_len = 16;
	src_struct.addr_ptr = nsp_addr;
	src_struct.socket_information = 0;
	src_struct.type = SN_NSDL_ADDRESS_TYPE_IPV6;
	src_struct.port = nsp_port;

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
						// parse data
						sn_nsdl_process_coap(rx_buffer, length, &src_struct);

					}
					 // Clear rx_buffer in order to avoid misunderstandings
					memset(rx_buffer,0,128);
			}	
		}
	}
    LED2_OFF();
#endif
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
	memcpy(app_dest.address, nsp_addr, 16);
	app_dest.identifier = nsp_port;
	app_dest.type = ADDRESS_IPV6;

	socket_sendto(app_udp_socket, &app_dest, data_ptr, data_len);

	return 0;
}

uint8_t rx_function(sn_coap_hdr_s *coap_header, sn_nsdl_addr_s *address_ptr)
{

	if(coap_header->msg_code == COAP_MSG_CODE_RESPONSE_CREATED)
	{
		reg_location_len = coap_header->options_list_ptr->location_path_len;

		if(reg_location)
			free(reg_location);

		reg_location = malloc(reg_location_len);
		if(!reg_location)
			return 0;

		memcpy(reg_location, coap_header->options_list_ptr->location_path_ptr, reg_location_len);
	}

	return 0;
}

static uint8_t relay_resource_cb(sn_coap_hdr_s *received_coap_ptr, sn_nsdl_addr_s *address, sn_proto_info_s * proto)
{
	sn_coap_hdr_s *coap_res_ptr = 0;

	if (received_coap_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
	{
		coap_res_ptr = sn_coap_build_response(received_coap_ptr, COAP_MSG_CODE_RESPONSE_CONTENT);
		coap_res_ptr->content_type_ptr = &text_plain;
		coap_res_ptr->content_type_len = sizeof(text_plain);
		coap_res_ptr->payload_len = sizeof(res_rel_val);
		coap_res_ptr->payload_ptr = &res_rel_val;
		sn_nsdl_send_coap_message(address, coap_res_ptr);

	}
	else if (received_coap_ptr->msg_code == COAP_MSG_CODE_REQUEST_PUT)
	{
		if (received_coap_ptr->payload_ptr && received_coap_ptr->payload_len < 2)
		{
			res_rel_val = received_coap_ptr->payload_ptr[0];
		}

		coap_res_ptr = sn_coap_build_response(received_coap_ptr, COAP_MSG_CODE_RESPONSE_CHANGED);
		if (received_coap_ptr->msg_type == COAP_MSG_TYPE_NON_CONFIRMABLE)
		{
			coap_res_ptr->msg_type = COAP_MSG_TYPE_NON_CONFIRMABLE;
			coap_res_ptr->msg_id = current_mid++;
		}
		sn_nsdl_send_coap_message(address, coap_res_ptr);
	}
	 /* Method not supported */
	else
	{
		coap_res_ptr = sn_coap_build_response(coap_res_ptr, COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED);
		sn_nsdl_send_coap_message(address, coap_res_ptr);
	}

	if(coap_res_ptr->token_ptr)
	{
		own_free(coap_res_ptr->token_ptr);
	}
	own_free(coap_res_ptr);

	return 0;
}

static uint8_t general_resource_cb(sn_coap_hdr_s *received_coap_ptr, sn_nsdl_addr_s *address, sn_proto_info_s * proto)
{
	sn_coap_hdr_s *coap_res_ptr = 0;

	if (received_coap_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET)
	{
		coap_res_ptr = sn_coap_build_response(received_coap_ptr, COAP_MSG_CODE_RESPONSE_CONTENT);
		coap_res_ptr->content_type_ptr = &text_plain;
		coap_res_ptr->content_type_len = sizeof(text_plain);

		if(compare_uripaths(received_coap_ptr, res_bat))
		{
			coap_res_ptr->payload_len = sizeof(res_bat_val)-1;
			coap_res_ptr->payload_ptr = res_bat_val;
		}
		else if(compare_uripaths(received_coap_ptr, res_pwr))
		{
			if(res_rel_val == '1')
			{
				coap_res_ptr->payload_len = sizeof(res_pwr_val)-1;
				coap_res_ptr->payload_ptr = res_pwr_val;
			}
			else if(res_rel_val == '0')
			{
				coap_res_ptr->payload_len = sizeof(res_pwr_val_off)-1;
				coap_res_ptr->payload_ptr = res_pwr_val_off;
			}
		}
		else if(compare_uripaths(received_coap_ptr, res_temp))
		{
			coap_res_ptr->payload_len = sizeof(res_temp_val)-1;
			coap_res_ptr->payload_ptr = res_temp_val;
		}

		else if(compare_uripaths(received_coap_ptr, res_gps))
		{
			coap_res_ptr->payload_len = sizeof(res_gps_val)-1;
			coap_res_ptr->payload_ptr = res_gps_val;
		}

		sn_nsdl_send_coap_message(address, coap_res_ptr);
	}
	 /* Method not supported */
	else
	{
		coap_res_ptr = sn_coap_build_response(coap_res_ptr, COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED);
		sn_nsdl_send_coap_message(address, coap_res_ptr);
	}

	if(coap_res_ptr->token_ptr)
	{
		own_free(coap_res_ptr->token_ptr);
	}
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

