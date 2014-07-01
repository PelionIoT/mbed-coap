/*
 * hal_sleep.c
 *
 *  Created on: 26.8.2011
 *      Author: user
 */

#include "hal_sn.h"
#include "system_event.h"


/* Variables for Sleeping  */
/* This will used for calculation for total sleep time */
volatile static PL_LARGE uint32_t total_sleep_time;
/* Saved Sleep timer count when start sleep sub period */
volatile static PL_LARGE uint32_t counter_val;
/* Sleep time left */
volatile static PL_LARGE uint32_t timer_sys_sleep_time = 0;
/* Indicate when external GPIO interrupt or Sleep timer wakeup was happen 1= Indicate sleep timer 0= External Interrupt */
volatile static PL_LARGE uint8_t wake_by_sl_timer = 0;

/**
 *  Sleep management Function
 *
 * \brief Set selected Power mode and config wakeup method. Function Call return sleep time
 * \param mode PM0/PM1/PM2/PM3 power state. Check datasheet which mode you want use
 * \param time sleep time period by 1/8 seconds (125ms)
 * \param gpio_wakeup 1=enable External GPIO interrupt for wake up 0= Sleep timer wakeup when sleep period is over.
 * \return unsigned 32bit sleeptime period by 1/8 seconds (125ms).
 *  If PM3 is selected function will return 65000 which should trig Librarys ND / RPL timers.
 */
uint32_t hal_sleep(pl_power_t mode, uint32_t time, uint8_t gpio_wakeup)
{
	uint32_t sleep_timer_cnt = 0;

	timer_sys_sleep_time = time;

	total_sleep_time  = 0;
	if(mode != POWER_PM3)
	{
		//Init Sleep Timer when PM3 is not selected
		sleep_timer_cnt = ST0;
		sleep_timer_cnt += ((unsigned long int)ST1) << 8;
		sleep_timer_cnt += ((unsigned long int)ST2) << 16;

		//Save Sleep Period
		counter_val = sleep_timer_cnt;
		counter_val &= 0x00ffffff;

		if (time > TIMER_PERIOD_MAX)
		{
			time = TIMER_PERIOD_MAX;
		}

		time <<= SLEEP_TIMER_SHIFT;
		sleep_timer_cnt += time;

		ST2 = (unsigned char) (sleep_timer_cnt >> 16);
		ST1 = (unsigned char) (sleep_timer_cnt >> 8);
		while(!(STLOAD & LDRDY));	/* Make sure that the LDRDY bit 0 is 1 before writing to ST0 */
		ST0 = (unsigned char) sleep_timer_cnt;

		IRCON_STIF=0;
		IEN0_STIE=1;
	}
	else
	{
		//Enable GPIO wakeup method aalways at PM3 mode
		gpio_wakeup=1;
		timer_sys_sleep_time = 1;
	}
	/*force sleep for first period*/
	wake_by_sl_timer = 1;
	while(timer_sys_sleep_time)
	{
		if(wake_by_sl_timer == 1)
		{
			SLEEPCMD = (SLEEPCMD & 0x80) | mode;
			PCON |= 0x01; /*enter sleep mode*/
			while(PCON & 0x01);
			wake_by_sl_timer = 0;
		}
		else if(gpio_wakeup)
		{
			if(mode != POWER_PM3)
			{
				sleep_timer_cnt = ST0;
				sleep_timer_cnt += ((unsigned long int)ST1) << 8;
				sleep_timer_cnt += ((unsigned long int)ST2) << 16;
				sleep_timer_cnt &= 0x00ffffff;
				if(sleep_timer_cnt > counter_val)
				{
					sleep_timer_cnt  = (sleep_timer_cnt -counter_val);
				}
				else
				{
					sleep_timer_cnt  = (counter_val - sleep_timer_cnt);
				}
				sleep_timer_cnt &= 0x00ffffff;
				//Converse to 1/8 sec period
				sleep_timer_cnt >>= SLEEP_TIMER_SHIFT;
				if(sleep_timer_cnt == 0)
				{
					sleep_timer_cnt = 1;
				}
				total_sleep_time += sleep_timer_cnt;
			}
			break;
		}

		else
		{
			wake_by_sl_timer = 1;
		}
	}

	if(mode == POWER_PM3)
	{
		//Can't know how long sleep then return big that ND & RPL will Check state
		return 65000;
	}
	return total_sleep_time;

}

/* Sleep timer Interrupt Handler*/
#pragma location="NEAR_CODE"
#pragma vector=ST_VECTOR
__interrupt void sleep_isr(void)
{
	lib_enter_critical();
	//Clear Current interrupt flag
    IRCON_STIF=0;

	if (timer_sys_sleep_time <= TIMER_PERIOD_MAX)
	{
		// Update total sleep time
        total_sleep_time += timer_sys_sleep_time;
        // Clear total Sleep time
		timer_sys_sleep_time = 0;
		//Disbale Sleep timer interrupt
		IEN0_STIE = 0;
	}
	else
	{
		//Sleep time still left set next period
		uint32_t sleep_timer_cnt = 0;
		//Read Current Sleep timer Counter
		sleep_timer_cnt = ST0;
		sleep_timer_cnt += ((unsigned long int)ST1) << 8;
		sleep_timer_cnt += ((unsigned long int)ST2) << 16;
		counter_val = sleep_timer_cnt;
        counter_val &= 0x00ffffff;
        // Update total sleep time
        total_sleep_time += TIMER_PERIOD_MAX;
        // Decraece sleep time left
		timer_sys_sleep_time -= TIMER_PERIOD_MAX;
		if (timer_sys_sleep_time <= TIMER_PERIOD_MAX)
		{
			//Set Last
			uint32_t tmp32 = timer_sys_sleep_time;
			tmp32 <<= SLEEP_TIMER_SHIFT;	/*CC2530 2^12 = 4096*/
			sleep_timer_cnt += tmp32;

		}
		else
		{
			uint32_t tmp32 = TIMER_PERIOD_MAX;
			tmp32 <<= SLEEP_TIMER_SHIFT; /*CC2530 time * 4096*/
			sleep_timer_cnt += tmp32;
		}
		ST2 = (unsigned char) (sleep_timer_cnt >> 16);
		ST1 = (unsigned char) (sleep_timer_cnt >> 8);
		while(!(STLOAD & LDRDY));	/* Make sure that the LDRDY bit 0 is 1 before writing to ST0 */
		ST0 = (unsigned char) sleep_timer_cnt;
	}
	//Set sleep timer interrupt to active
    wake_by_sl_timer = 1;
    lib_exit_critical();
}
