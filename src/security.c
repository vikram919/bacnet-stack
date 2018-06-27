/*
 * security.c
 *
 *  Created on: 03.05.2018
 *      Author: mn204
 */

#include <stdbool.h>
#include <time.h>
#include <string.h>
#include "iniReader.h"
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

	// increment message id counter
	wrapper.message_id++;

    // timestamp: standard UNIX timestamp
    wrapper.timestamp = time(NULL);
    wrapper.destination_device_instance = device_id;

    // destination and source network information
    wrapper.dnet = dest->net;
    wrapper.dlen = dest->mac_len;
    memcpy(wrapper.dadr, dest->mac, wrapper.dlen);

    wrapper.snet = src->net;
    wrapper.slen = src->mac_len;
    memcpy(wrapper.sadr, src->mac, wrapper.slen);

	return 0;
}

int initialize_security_wrapper() {

	// FIXME: no initialization leads to error in rp_encode_apdu
	uint8_t test[MAX_APDU];
	wrapper.service_data = test;

	/* set bits of control octet */
	parseIniFile("../config.ini");

	char *payload_net_or_bvll_flag[60];
	char *encrypted_flag[60];
	char *authentication_flag[60];
	char *do_not_unwrap_flag[60];
	char *do_not_decrypt_flag[60];
	char *non_trusted_source_flag[60];
	char *secured_by_router_flag[60];
	char *key_identifier[60];

	printf("---------------------------------\n");

	// payload_net_or_bvll_flag
	if (getConfigValue(payload_net_or_bvll_flag, "payload_net_or_bvll_flag") != 1){
			printf("Can not find 'payload_net_or_bvll_flag' in configuration file.");
			return(-1);
	}

	else{
		printf("payload_net_or_bvll_flag: %s\n", payload_net_or_bvll_flag);
		if(!strcmp(payload_net_or_bvll_flag, "true")) {
			wrapper.payload_net_or_bvll_flag = true;
		}
		else {
			wrapper.payload_net_or_bvll_flag = false;
		}
	}

	// encrypted_flag
	if (getConfigValue(encrypted_flag, "encrypted_flag") != 1){
			printf("Can not find 'encrypted_flag' in configuration file.\n");
			return(-1);
	}
	else{
		printf("encrypted_flag: %s\n", encrypted_flag);
		if(!strcmp(encrypted_flag, "true")) {
			wrapper.encrypted_flag = true;
		}
		else {
			wrapper.encrypted_flag = false;
		}
	}

	// authentication_flag
	if (getConfigValue(authentication_flag, "authentication_flag") != 1){
		printf("Can not find 'authentication_flag' in configuration file.\n");
		return(-1);
	}
	else{
		printf("authentication_flag: %s\n", authentication_flag);
		if(!strcmp(authentication_flag, "true")) {
			wrapper.authentication_flag = true;
		}
		else {
			wrapper.authentication_flag = false;
		}
	}

	// do_not_unwrap_flag
	if (getConfigValue(do_not_unwrap_flag, "do_not_unwrap_flag") != 1){
		printf("Can not find 'do_not_unwrap_flag' in configuration file.");
		return(-1);
	}
	else{
		printf("do_not_unwrap_flag: %s\n", do_not_unwrap_flag);
		if(!strcmp(do_not_unwrap_flag, "true")) {
			wrapper.do_not_unwrap_flag = true;
		}
		else {
			wrapper.do_not_unwrap_flag = false;
		}
	}

	// do_not_decrypt_flag
	if (getConfigValue(do_not_decrypt_flag, "do_not_decrypt_flag") != 1){
		printf("Can not find 'do_not_decrypt_flag' in configuration file.");
		return(-1);
	}
	else{
		printf("do_not_decrypt_flag: %s\n", do_not_decrypt_flag);
		if(!strcmp(do_not_decrypt_flag, "true")) {
			wrapper.do_not_decrypt_flag = true;
		}
		else {
			wrapper.do_not_decrypt_flag = false;
		}
	}

	// non_trusted_source_flag
	if (getConfigValue(non_trusted_source_flag, "non_trusted_source_flag") != 1){
		printf("Can not find 'non_trusted_source_flag' in configuration file.");
		return(-1);
	}
	else{
		printf("non_trusted_source_flag: %s\n", non_trusted_source_flag);
		if(!strcmp(non_trusted_source_flag, "true")) {
			wrapper.non_trusted_source_flag = true;
		}
		else {
			wrapper.non_trusted_source_flag = false;
		}
	}

	// secured_by_router_flag
	if (getConfigValue(secured_by_router_flag, "secured_by_router_flag") != 1){
			printf("Can not find 'secured_by_router_flag' in configuration file.");
			return(-1);
	}
	else{
		printf("secured_by_router_flag: %s\n", secured_by_router_flag);
		if(!strcmp(secured_by_router_flag, "true")) {
			wrapper.secured_by_router_flag = true;
		}
		else {
			wrapper.secured_by_router_flag = false;
		}
	}

	// key identifier:
	// 1 for DEVICE_MASTER_KEY and AES/MD5
	// 257 for DEVICE_MASTER_KEY and AES/SHA-256
	if (getConfigValue(key_identifier, "key_identifier") != 1) {
		printf("Can not find 'key_identifier' in configuration file.");
		return(-1);
	}
	else {

		int key_id = atoi(key_identifier);
		if(key_id == 1){
			printf("Using AES/MD5\n");
		}
		else if(key_id == 257) {
			printf("Using AES/SHA-256\n");
		}
		wrapper.key_identifier = key_id;
	}
	printf("---------------------------------\n");
	wrapper.key_revision = 0;

	wrapper.source_device_instance = 1;
	// message id: 32 bit integer, increased by 1 for each message
	wrapper.message_id = 0;

	// set authentication data
	wrapper.authentication_mechanism = 0;
	wrapper.user_id = 0;
	wrapper.user_role = 0;

	return 0;
}

