/**
 * \file 	main.c
 *
 * \brief	Command line parameter parsing for Connected Home server
 *
 * \author 	Zach Shelby <zach@sensinode.com>
 *
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include "sn_nsdl.h"
#include "sn_coap_header.h"
#include "sn_coap_protocol.h"
#include "sn_nsdl_lib.h"
#include "ns_list.h"
#include "arguments.h"

#define NUMTHREADS 10

extern int register_endpoint(int port, sn_nsdl_ep_parameters_s *endpoint_ptr, int thread_id);
void stop_pgm(char *s)
{
	perror(s);
	exit(1);
}

void *own_alloc(uint16_t size)
{
    if(size) {
        return malloc(size);
    }
    else {
        return 0;
    }
}

void own_free(void *ptr)
{
    free(ptr);
}

/* function to be executed by the new thread */
void* create_endpoint(void *arg)
{    
    int index = *((int *) arg);
    int port = 8100 + index;
    sn_nsdl_ep_parameters_s *endpoint_ptr;
    uint8_t endpoint_type[] = {"type"};
    uint8_t lifetime_ptr[] = {"120"};
    char str[10];
    sprintf(str, "THREAD_%d", index);
    endpoint_ptr = own_alloc(sizeof(sn_nsdl_ep_parameters_s));
    if(endpoint_ptr)
    {
        memset(endpoint_ptr, 0, sizeof(sn_nsdl_ep_parameters_s));
        endpoint_ptr->endpoint_name_ptr = str;
        endpoint_ptr->endpoint_name_len = strlen(str);
        endpoint_ptr->type_ptr = endpoint_type;
        endpoint_ptr->type_len =  sizeof(endpoint_type)-1;
        endpoint_ptr->lifetime_ptr = lifetime_ptr;
        endpoint_ptr->lifetime_len =  sizeof(lifetime_ptr)-1;
    }
    register_endpoint(port, endpoint_ptr, index);
    if(endpoint_ptr) {
        own_free(endpoint_ptr);
        endpoint_ptr = 0;
    }    
}

int main()
{    
    pthread_t threads[NUMTHREADS];
    for (int index = 0; index < NUMTHREADS; index++) {        
        pthread_create(&threads[index], NULL, create_endpoint, (void *) &index);        
        sleep(1);
    }

    for (int i = 0; i < NUMTHREADS; i) {
        pthread_join(threads[i], NULL);
    }
    exit(0);
}



