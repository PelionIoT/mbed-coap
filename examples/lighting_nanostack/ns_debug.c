
/**
 * Copyright Sensinode Ltd 2011
 * \file Lib/hal/common/ns_debug.c
 * \brief debug and other platform compile-time configuration
 *
 */

#include <string.h>
#include "system_event.h"
#include "ns_debug.h"
#include "hal_sn.h"

extern void debug_send(uint8_t *str);
extern void debug_send_const(prog_uint8_t *str);

int8_t debug_init(uint32_t speed, uint8_t io_conf);
extern int16_t debug_get(void);
extern int8_t debug_put(uint8_t byte);
extern void debug_open(void);
extern void debug_close(void);

void debug_integer(uint8_t width, uint8_t base, int16_t n);



void printf_array(uint8_t *ptr , uint16_t len);
void printf_string(uint8_t *ptr , uint16_t len);

int8_t debug_hw_init(uint32_t speed, uint8_t ioconf);




/**
 * \brief This function initializes debugs and is called from main.c.
 */
int8_t debug_init(uint32_t speed, uint8_t io_conf)
{
  int8_t retval = debug_hw_init(speed, io_conf);
  return retval;
}


/**
 * \brief This function initializes debug hardware by setting predefined baud rate
 * \warning hardware is hard coded only to use 115200
 */
int8_t debug_hw_init(uint32_t speed, uint8_t ioconf)
{
	int8_t retval = uart_init(speed, ioconf);
	event_system_alloc(DBU_EVENT);
	return retval;
}

/**
 * \brief open debug receiver.
 *
 */
void debug_open(void)
{
  DBU_OPEN();
}

/**
 * \brief closes debug connection.
 *
 */
void debug_close(void)
{
  DBU_CLOSE();
}

/**
 * \brief gets signed 16 bits from uart queues.
 * \return signed 16 bit result from queue.
 */
int16_t debug_get(void)
{
  return DBU_GET();
}

/**
 * \brief puts one byte to uart tx queue.
 * \param byte which is the byte to put to queue.
 * \return value returned by DBU_PUT macro.
 */
int8_t debug_put(uint8_t byte)
{
  return DBU_PUT(byte);
}

void debug_send(uint8_t *str)
{
	DBU_SEND(str);
}

void debug_send_const(prog_uint8_t *str)
{
	DBU_CONST(str);
}

/**
 * Print a number to the debug port.
 *
 * \param width string maximum length
 * \param base base number (16 for hex, 10 for decimal etc.)
 * \param n number value
 *
 * \return pointer to the formatted string
 */
void debug_integer(uint8_t width, uint8_t base, int16_t n)
{
  uint8_t bfr[8];
  uint8_t *ptr = bfr;
  uint8_t ctr = 0;

  if (width > 7) width = 7;

  ptr += width;
  *ptr-- = 0;

  if (base == 16)
  {
      do
      {
          *ptr = n & 0x0F;
          if (*ptr < 10) *ptr += '0';
          else *ptr += ('A'-10);
          ptr--;
          n >>= 4;
          ctr++;
      }while((ctr & 1) || (ctr < width));
  }
  else
  {
      uint8_t negative = 0;
      if (n < 0)
      { negative = 1;
        n = -n;
      }
      ctr++;
      do
      {
        *ptr-- = (n % 10) + '0';
        n /= 10;
        ctr++;
      }while ((ctr < width) && n);
      if (negative)
      {
        *ptr-- = '-';
      }
      else
      {
        *ptr-- = ' ';
      }
  }
  ptr++;
  debug_send(ptr);
}

void printf_array(uint8_t *ptr , uint16_t len)
{
	uint16_t i;
	for(i=0; i<len; i++)
	{
		if(i)
		{
			if(i%16== 0)
			{
				debug_send_const("\r\n");
				if(len > 64)
				{
					uint8_t x =254;
					while(x--);
				}
			}
			else
			{
				debug_send_const(":");
			}
		}
		debug_hex(*ptr++);
	}
	debug_send_const("\r\n");
}

void printf_string(uint8_t *ptr , uint16_t len)
{
	//uint8_t i;
	while(len--)
	{
		if(*ptr == 0)
		{
			break;
		}
		else
		{
			DBU_PUT(*ptr++);
		}
	}
	debug_send_const("\r\n");
}
/**
 * Print a IPv6 address.
 *
 * \param addr_ptr pointer to ipv6 address
 *
 */
void printf_ipv6_address(uint8_t *addr_ptr)
{
	if(addr_ptr)
	{
		uint8_t i, d_colon = 0;
		uint16_t current_value = 0, last_value = 0;

		for(i=0; i< 16;i += 2)
		{
			current_value =  (*addr_ptr++ << 8);
			current_value += *addr_ptr++;

			if(i == 0)
			{
				last_value = current_value;
				debug_hex(current_value >> 8);
				debug_hex(current_value );
				debug(":");
			}
			else
			{
				if(current_value == 0)
				{
					if(i== 14)
					{
						debug(":");
						debug_put('0');
					}
					else
					{
						if(last_value == 0)
						{
							if(d_colon == 0)
							{
								d_colon=1;
							}
						}
						else
						{
							if(d_colon == 2)
							{
								DBU_PUT('0');
								debug(":");
							}
						}
					}
				}
				else
				{
					if(last_value == 0)
					{
						if(d_colon == 1)
						{
							debug(":");
							d_colon = 2;
						}
						else
						{
							DBU_PUT('0');
							debug(":");
						}
					}
					if(current_value > 0x00ff)
					{
						debug_hex(current_value >> 8);
					}
					debug_hex(current_value );
					if(i< 14)
					{
						debug(":");
					}
				}
				last_value = current_value;
			}
		}
	}
	else
	{
		debug("Address Print: pointer NULL");
	}
	debug("\r\n");
}

