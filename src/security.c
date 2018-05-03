/*
 * security.c
 *
 *  Created on: 03.05.2018
 *      Author: mn204
 */

#include <stdbool.h>
#include <time.h>
#include <string.h>
#include "security.h"

BACNET_SECURITY_WRAPPER wrapper = { 0 };

int set_npdu_data(BACNET_NPDU_DATA * npdu_data,
	BACNET_NETWORK_MESSAGE_TYPE type) {
	if(!npdu_data)
		return -1;
	npdu_data->network_layer_message = true;
	npdu_data->network_message_type = NETWORK_MESSAGE_SECURITY_PAYLOAD;
	return 0;
}

int set_security_wrapper_fields_static(uint32_t device_id,
	BACNET_ADDRESS * dest,
	BACNET_ADDRESS * src) {

	if(!dest)
		return -1;

	if(!src)
		return -1;

	/* set bits of control octet */
    wrapper.payload_net_or_bvll_flag = false;
    wrapper.encrypted_flag = true;
    // bit 5: reserved, shall be zero
    wrapper.authentication_flag = false;
    wrapper.do_not_unwrap_flag = false;
    wrapper.do_not_decrypt_flag = false;
    wrapper.non_trusted_source_flag = false;
    wrapper.secured_by_router_flag = false;

    // key identifier: 0 indicates device master key
    wrapper.key_identifier = KIKN_DEVICE_MASTER;
    wrapper.key_revision = 0;
    wrapper.source_device_instance = 1;
    // message id: 32 bit integer, increased by 1 for each message
    // for now it is always 1
    wrapper.message_id = 1;
    // timestamp: standard UNIX timestamp
    wrapper.timestamp = time(NULL);
    wrapper.destination_device_instance = device_id;

    // destination and source network information
    wrapper.dnet = dest->net;
    wrapper.dlen = sizeof(dest->adr);
    memcpy(wrapper.dadr, dest->adr, wrapper.dlen);
    wrapper.snet = src->net;
//        wrapper.slen = my_address.len;
    wrapper.slen = sizeof(src->adr);
    memcpy(wrapper.sadr, src->adr, wrapper.slen);

    wrapper.authentication_mechanism = 0;
    wrapper.user_id = 0;
    wrapper.user_role = 0;

	return 0;
}


