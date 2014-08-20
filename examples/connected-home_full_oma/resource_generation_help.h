/*
 * resource_generation_help.h
 *
 *  Created on: 6.3.2012
 *      Author: Sensinode
 */

#ifndef RESOURCE_GENERATION_HELP_H_
#define RESOURCE_GENERATION_HELP_H_

/*
 * A helper macro to create a static resoure
 */
#define CREATE_STATIC_RESOURCE(resource_structure, pt_len, pt, rpp_len, rpp_ptr, rsc, rsc_len) 		\
{																									\
	resource_structure->access = (sn_grs_resource_acl_e)0xff;										\
	resource_structure->mode = SN_GRS_STATIC;														\
	resource_structure->pathlen = pt_len; 															\
	resource_structure->path = pt; 																	\
	resource_structure->resource_parameters_ptr->resource_type_len = rpp_len; 						\
	resource_structure->resource_parameters_ptr->resource_type_ptr = rpp_ptr; 						\
	resource_structure->resource = rsc; 															\
	resource_structure->resourcelen = rsc_len;														\
	sn_nsdl_create_resource(resource_structure); 													\
}


/*
 * A helper macro to create a dynamic resoure
 */
#define CREATE_DYNAMIC_RESOURCE(resource_structure, pt_len, pt, rpp_len, rpp_ptr, is_observable, callback_ptr) 	\
{																									\
	resource_structure->access = (sn_grs_resource_acl_e)0xff;										\
	resource_structure->resource = 0;																\
	resource_structure->resourcelen = 0;															\
	resource_structure->sn_grs_dyn_res_callback = callback_ptr;								\
	resource_structure->mode = SN_GRS_DYNAMIC;														\
	resource_structure->pathlen = pt_len; 															\
	resource_structure->path = pt; 																	\
	resource_structure->resource_parameters_ptr->resource_type_len = rpp_len; 						\
	resource_structure->resource_parameters_ptr->resource_type_ptr = rpp_ptr; 						\
	resource_structure->resource_parameters_ptr->observable = is_observable; 						\
	sn_nsdl_create_resource(resource_structure); 													\
}

#define INIT_REGISTER_NSDL_ENDPOINT(endpoint_structure, name, typename_ptr, lifetime_ptr)				\
{																									\
			if(!endpoint_structure)																	\
			{																						\
				endpoint_structure = own_alloc(sizeof(sn_nsdl_ep_parameters_s));					\
			}																						\
			if(endpoint_structure)																	\
			{																						\
				memset(endpoint_structure, 0, sizeof(sn_nsdl_ep_parameters_s));						\
				endpoint_structure->endpoint_name_ptr = name;										\
				endpoint_structure->endpoint_name_len = sizeof(name)-1;								\
				endpoint_structure->type_ptr = typename_ptr;										\
				endpoint_structure->type_len =  sizeof(typename_ptr)-1;								\
				endpoint_structure->lifetime_ptr = lifetime_ptr;									\
				endpoint_structure->lifetime_len =  sizeof(lifetime_ptr)-1;							\
			}																						\
}

#define CLEAN_REGISTER_NSDL_ENDPOINT(endpoint_structure)											\
{																									\
			if(endpoint_structure)																	\
			{																						\
				own_free(endpoint_structure);														\
				endpoint_structure = 0;																	\
			}																						\
}																									\

#endif /* RESOURCE_GENERATION_HELP_H_ */
