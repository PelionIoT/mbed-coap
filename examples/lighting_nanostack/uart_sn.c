


#include "socket_api.h"
#include "system_event.h"
#include "string.h"
#include "pl_types.h"
#include "ns_debug.h"
#include "hal_sn.h"
#define RX_ON 1
#define TX_ON 2


#define UART_RX_LEN 30
#define UART_TX_LEN 290

#if NS_DEBUG_UART == 0
#define UART_BAUD U0BAUD
#define UART_GCR  U0GCR
#define UART_UCR  U0UCR
#define UART_CSR  U0CSR
#define UART_BUF  U0BUF_SHADOW
#define USRT_HARD_BUF U0BUF
#define UART_RX_INT_ENABLE IEN0_URX0IE
#define UART_TX_INT UTX0IE
#define UART_TX_INT_ENABLE IRCON2_UTX0IF
#define UART_RX_INT_CLEAR {TCON_URX0IF=0;}

/*UART 0 I/O 1*/
/*alternative port 1 = P0.5-2*/
#define UART_IO_INIT1 {PERCFG &= ~U0CFG;P0SEL |= 0x0C;P0DIR |= 0x08;P0DIR &= ~0x04;}
/*UART 0 I/O 2*/
/*alternative port 2 = P1.5-2*/
#define	UART_IO_INIT2 {PERCFG |= U0CFG;P1SEL |= 0x30;P1DIR |= 0x20;P1DIR &= ~0x10;}
#else
#define UART_BAUD U1BAUD
#define UART_GCR  U1GCR
#define UART_UCR  U1UCR
#define UART_CSR  U1CSR
#define UART_BUF  U1BUF_SHADOW
#define USRT_HARD_BUF U1BUF
#define UART_RX_INT_ENABLE IEN0_URX1IE
#define UART_TX_INT UTX1IE
#define UART_TX_INT_ENABLE IRCON2_UTX1IF
#define UART_RX_INT_CLEAR {TCON_URX1IF=0;}
/*UART 1 I/O 1*/
/*alternative port 1 = P0.5-2*/
#define	UART_IO_INIT1 {PERCFG &= ~U1CFG;P0SEL |= 0x30; P0DIR |= 0x10;P0DIR &= ~0x20;}
/*UART 1 I/O 2*/
/*alternative port 2 = P1.7-4*/
#define UART_IO_INIT2 {PERCFG |= U1CFG;P1SEL |= 0xC0;P1DIR |= 0x40; /*P1 &= ~0x20;*/}
#endif

/** The queue used to hold received characters. */
PL_LARGE uint8_t uart_rx_buffer[UART_RX_LEN];
PL_LARGE uint8_t uart_rx_rd = 0;
PL_LARGE uint8_t uart_rx_wr = 0;
PL_LARGE uint8_t uart_tx_buffer[UART_TX_LEN];
PL_LARGE uint16_t uart_tx_rd = 0;
PL_LARGE uint16_t uart_tx_wr = 0;

int8_t uart_init(uint32_t speed, uint8_t io_conf)
{
	uart_rx_rd = 0;
	uart_rx_wr = 0;
	uart_tx_rd = 0;
	uart_tx_wr = 0;
	/*Baud rate = ((256+UxBAUD) * 2^UxGCR)*crystal / (2^28)*/
	#if NS_DEBUG_UART == 0
	if(io_conf == 0)
	{
		//PIN ALT 1
		UART_IO_INIT1
	}
	else
	{
		//PIN ALT 2
		UART_IO_INIT2
	}
	#else
	if(io_conf == 0)
	{
		//PIN ALT 1
		UART_IO_INIT1
	}
	else
	{
		//PIN ALT 2
		UART_IO_INIT2
	}
	#endif

	switch(speed)
	{
		case 115200:
			UART_BAUD=216;
			UART_GCR = 11; /*LSB first and 115200 = 11 , 13 460800 */
			break;
		case 230400:
			UART_BAUD=216;
			UART_GCR = 12; /*LSB first and 230400 */
			break;
		case 460800:
			UART_BAUD=216;
			UART_GCR = 13; /*LSB first and 115200 = 11 , 13 460800 */
			break;
		default:
			if (speed < 256)
			{
				UART_BAUD=216;		/*115200*/
				UART_GCR = speed; /*LSB first and 115200 = 11 , 13 460800 */
			}
			else return -1;
	}

	UART_UCR = 0x02;			/*defaults: 8N1, no flow control, high stop bit*/
	UART_CSR = U_MODE | U_RE |U_TXB; /*UART mode, receiver enable, TX done*/
	UART_RX_INT_ENABLE = 1;
	UART_RX_INT_CLEAR
	return 0;
}

void uart_receiver_off(void)
{
	if(UART_CSR & U_RE)
	{
		UART_CSR &= ~U_RE;
		UART_RX_INT_ENABLE = 0;
		IEN2 &= ~UART_TX_INT;
	}
}

void uart_receiver_on(void)
{
	if(!(UART_CSR & U_RE))
	{
		UART_CSR |= U_RE;
		UART_RX_INT_ENABLE = 1;
		if (uart_tx_rd != uart_tx_wr)
		{
			IEN2 |= UART_TX_INT;
		}
	}
}

int16_t uart_get(void)
{

	uint8_t rx_byte;

	if (uart_rx_rd != uart_rx_wr)
	{
		uint8_t ptr = uart_rx_rd;
		lib_enter_critical();
		rx_byte = uart_rx_buffer[ptr++];
		if (ptr >= UART_RX_LEN) ptr = 0;
		uart_rx_rd = ptr;
		lib_exit_critical();
		return rx_byte;
	}
	else
	{
		return -1;
	}
}

int8_t uart_put(uint8_t byte)
{
	int8_t retval = 0;
	uint16_t new_ptr = uart_tx_wr +1;
	uart_receiver_on();

	if (new_ptr >= UART_TX_LEN) new_ptr = 0;
		if (new_ptr == uart_tx_rd)
		{
			retval = -1;
		}
		else
		{
			lib_enter_critical();
			uart_tx_buffer[uart_tx_wr] = byte;
			uart_tx_wr = new_ptr;
			if ((IEN2 & UART_TX_INT) == 0)
			{

	/*			uart1_tx_rd = new_ptr;
				U1BUF = byte;*/
				IEN2 |= UART_TX_INT;
				UART_TX_INT_ENABLE =1;
				//IRCON2_UTX1IF = 1;

			}
			lib_exit_critical();
		}
	return retval;
}

void uart_put_str(uint8_t *str)
{
	lib_enter_critical();
	while(*str)
	{
		uart_put(*str++);

	}
	lib_exit_critical();
}

void uart_put_const(prog_uint8_t *str)
{
	lib_enter_critical();
	while(*str)
	{
		uart_put(*str++);
	}
	lib_exit_critical();
}

/**
 * UART RX interrupt service routine
 * for UART 0
 */


#pragma location="NEAR_CODE"
#if NS_DEBUG_UART == 0
#pragma vector=URX0_VECTOR
__interrupt void uart0_rxISR(void)
#else
#pragma vector=URX1_VECTOR
__interrupt void uart1_rxISR(void)
#endif
{
	uint8_t ptr;
	lib_enter_critical();
	/* Get the character from the UART and post it on the queue of Rxed
	characters. */
	UART_RX_INT_CLEAR
	/* Get the character from the UART and post it on the queue of Rxed
	characters. */
	ptr = uart_rx_wr;
	ptr++;
	if (ptr >= UART_RX_LEN) ptr = 0;
	if (ptr != uart_rx_rd)
	{
		uart_rx_buffer[uart_rx_wr] = USRT_HARD_BUF;
		uart_rx_wr	= ptr;
	}
	else
	{
		ptr = USRT_HARD_BUF;
		//LED1_ON();
		/*uart1_error |= 0x01;*/
	}
	{
		event_t event;
		event.receiver = TL_MAIN;
		event.sender = SYSTEM;
		event.event = EV_UART0;
		event_send(&event);
	}
	lib_exit_critical();
}


/**
 * UART Tx interrupt service routine.
 * for UART 0
 */

#pragma location="NEAR_CODE"
#if NS_DEBUG_UART == 0
#pragma vector=UTX0_VECTOR
__interrupt void uart0_txISR(void)
#else
#pragma vector=UTX1_VECTOR
__interrupt void uart1_txISR(void)
#endif
{
	lib_enter_critical();
	UART_TX_INT_ENABLE = 0;
	if (uart_tx_rd != uart_tx_wr)
	{
		USRT_HARD_BUF = uart_tx_buffer[uart_tx_rd++];
		if (uart_tx_rd >= UART_TX_LEN) uart_tx_rd = 0;
	}
	else
	{

		IEN2 &= ~UART_TX_INT;
	}

	lib_exit_critical();
}
