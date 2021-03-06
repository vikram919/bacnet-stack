/**************************************************************************
*
* Copyright (C) 2006 Steve Karg <skarg@users.sourceforge.net>
*
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
*
* The above copyright notice and this permission notice shall be included
* in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
*********************************************************************/
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>

#include "config.h"
#include "server.h"
#include "address.h"
#include "bacdef.h"
#include "handlers.h"
#include "client.h"
#include "dlenv.h"
#include "bacdcode.h"
#include "npdu.h"
#include "apdu.h"
#include "iam.h"
#include "tsm.h"
#include "device.h"
#include "bacfile.h"
#include "datalink.h"
#include "dcc.h"
#include "filename.h"
#include "getevent.h"
#include "net.h"
#include "txbuf.h"
#include "lc.h"
#include "version.h"
/* include the device object */
#include "device.h"
#include "trendlog.h"
#if defined(INTRINSIC_REPORTING)
#include "nc.h"
#endif /* defined(INTRINSIC_REPORTING) */
#if defined(BACFILE)
#include "bacfile.h"
#endif /* defined(BACFILE) */
#if defined(BAC_UCI)
#include "ucix.h"
#endif /* defined(BAC_UCI) */

#if SECURITY_ENABLED
#include "bacsec.h"
#include "security.h"
#endif

// define key, for now we us the same key for each device
// FIXME: implement key server
uint8_t KEY[] = {
	(uint8_t) 0x97, (uint8_t) 0xEC, (uint8_t) 0x8A, (uint8_t) 0xEF,
	(uint8_t) 0x9E, (uint8_t) 0x2C, (uint8_t) 0x94, (uint8_t) 0x47,
	(uint8_t) 0x96, (uint8_t) 0xEB, (uint8_t) 0x13, (uint8_t) 0x5A,
	(uint8_t) 0x11, (uint8_t) 0x55, (uint8_t) 0xB0, (uint8_t) 0x4D,
	// 256 bit SHA-256
	(uint8_t) 0xB0, (uint8_t) 0x54, (uint8_t) 0xFB, (uint8_t) 0xE5,
	(uint8_t) 0xAA, (uint8_t) 0x53, (uint8_t) 0xB0, (uint8_t) 0xD9,
	(uint8_t) 0x05, (uint8_t) 0x26, (uint8_t) 0x3F, (uint8_t) 0x10,
	(uint8_t) 0x3A, (uint8_t) 0xD0, (uint8_t) 0x3D, (uint8_t) 0x65,
	(uint8_t) 0xEE, (uint8_t) 0x2D, (uint8_t) 0x92, (uint8_t) 0x68,
	(uint8_t) 0xA9, (uint8_t) 0xAB, (uint8_t) 0x23, (uint8_t) 0x3B,
	(uint8_t) 0xE5, (uint8_t) 0x37, (uint8_t) 0x66, (uint8_t) 0x90,
	(uint8_t) 0x73, (uint8_t) 0xC9, (uint8_t) 0x64, (uint8_t) 0x75
};

/** @file server/main.c  Example server application using the BACnet Stack. */

/* (Doxygen note: The next two lines pull all the following Javadoc
 *  into the ServerDemo module.) */
/** @addtogroup ServerDemo */
/*@{*/

/** Buffer used for receiving */
static uint8_t Rx_Buf[MAX_MPDU] = { 0 };

/** Initialize the handlers we will utilize.
 * @see Device_Init, apdu_set_unconfirmed_handler, apdu_set_confirmed_handler
 */
static void Init_Service_Handlers(
    void)
{
    Device_Init(NULL);
    /* we need to handle who-is to support dynamic device binding */
    apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_WHO_IS, handler_who_is);
    apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_WHO_HAS, handler_who_has);

#if 0
	/* 	BACnet Testing Observed Incident oi00107
		Server only devices should not indicate that they EXECUTE I-Am
		Revealed by BACnet Test Client v1.8.16 ( www.bac-test.com/bacnet-test-client-download )
			BITS: BIT00040
		Any discussions can be directed to edward@bac-test.com
		Please feel free to remove this comment when my changes accepted after suitable time for
		review by all interested parties. Say 6 months -> September 2016 */
	/* In this demo, we are the server only ( BACnet "B" device ) so we do not indicate
	   that we can execute the I-Am message */
    /* handle i-am to support binding to other devices */
    apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_I_AM, handler_i_am_bind);
#endif

    /* set the handler for all the services we don't implement */
    /* It is required to send the proper reject message... */
    apdu_set_unrecognized_service_handler_handler
        (handler_unrecognized_service);
    /* Set the handlers for any confirmed services that we support. */
    /* We must implement read property - it's required! */
    apdu_set_confirmed_handler(SERVICE_CONFIRMED_READ_PROPERTY,
        handler_read_property);
    apdu_set_confirmed_handler(SERVICE_CONFIRMED_READ_PROP_MULTIPLE,
        handler_read_property_multiple);
    apdu_set_confirmed_handler(SERVICE_CONFIRMED_WRITE_PROPERTY,
        handler_write_property);
    apdu_set_confirmed_handler(SERVICE_CONFIRMED_WRITE_PROP_MULTIPLE,
        handler_write_property_multiple);
    apdu_set_confirmed_handler(SERVICE_CONFIRMED_READ_RANGE,
        handler_read_range);
#if defined(BACFILE)
    apdu_set_confirmed_handler(SERVICE_CONFIRMED_ATOMIC_READ_FILE,
        handler_atomic_read_file);
    apdu_set_confirmed_handler(SERVICE_CONFIRMED_ATOMIC_WRITE_FILE,
        handler_atomic_write_file);
#endif
    apdu_set_confirmed_handler(SERVICE_CONFIRMED_REINITIALIZE_DEVICE,
        handler_reinitialize_device);
    apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_UTC_TIME_SYNCHRONIZATION,
        handler_timesync_utc);
    apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_TIME_SYNCHRONIZATION,
        handler_timesync);
    apdu_set_confirmed_handler(SERVICE_CONFIRMED_SUBSCRIBE_COV,
        handler_cov_subscribe);
    apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_COV_NOTIFICATION,
        handler_ucov_notification);
    /* handle communication so we can shutup when asked */
    apdu_set_confirmed_handler(SERVICE_CONFIRMED_DEVICE_COMMUNICATION_CONTROL,
        handler_device_communication_control);
    /* handle the data coming back from private requests */
    apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_PRIVATE_TRANSFER,
        handler_unconfirmed_private_transfer);
#if defined(INTRINSIC_REPORTING)
    apdu_set_confirmed_handler(SERVICE_CONFIRMED_ACKNOWLEDGE_ALARM,
        handler_alarm_ack);
    apdu_set_confirmed_handler(SERVICE_CONFIRMED_GET_EVENT_INFORMATION,
        handler_get_event_information);
    apdu_set_confirmed_handler(SERVICE_CONFIRMED_GET_ALARM_SUMMARY,
        handler_get_alarm_summary);
#endif /* defined(INTRINSIC_REPORTING) */
#if defined(BACNET_TIME_MASTER)
    handler_timesync_init();
#endif
}

static void print_usage(const char *filename)
{
    printf("Usage: %s [device-instance [device-name]]\n", filename);
    printf("       [--version][--help]\n");
}

static void print_help(const char *filename)
{
    printf("Simulate a BACnet server device\n"
        "device-instance:\n"
        "BACnet Device Object Instance number that you are\n"
        "trying simulate.\n"
        "device-name:\n"
        "The Device object-name is the text name for the device.\n"
        "\nExample:\n");
    printf("To simulate Device 123, use the following command:\n"
        "%s 123\n", filename);
    printf("To simulate Device 123 named Fred, use following command:\n"
        "%s 123 Fred\n", filename);
}

/** Main function of server demo.
 *
 * @see Device_Set_Object_Instance_Number, dlenv_init, Send_I_Am,
 *      datalink_receive, npdu_handler,
 *      dcc_timer_seconds, bvlc_maintenance_timer,
 *      Load_Control_State_Machine_Handler, handler_cov_task,
 *      tsm_timer_milliseconds
 *
 * @param argc [in] Arg count.
 * @param argv [in] Takes one argument: the Device Instance #.
 * @return 0 on success.
 */
int main(
    int argc,
    char *argv[])
{

#if SECURITY_ENABLED
	// initialize security wrapper
	initialize_security_wrapper();

	// set master key
	BACNET_KEY_ENTRY key;
	key.key_identifier = wrapper.key_identifier;
	key.key_len = sizeof(KEY);
	memcpy(key.key, &KEY, sizeof(KEY));

	BACNET_SET_MASTER_KEY master;

	memcpy(&master, &key, sizeof(BACNET_KEY_ENTRY));

	if(bacnet_master_key_set(&master) != SEC_RESP_SUCCESS)
		return 0;
#endif


    BACNET_ADDRESS src = {
        0
    };  /* address where message came from */
    uint16_t pdu_len = 0;
    unsigned timeout = 1;       /* milliseconds */
    time_t last_seconds = 0;
    time_t current_seconds = 0;
    uint32_t elapsed_seconds = 0;
    uint32_t elapsed_milliseconds = 0;
    uint32_t address_binding_tmr = 0;
    uint32_t recipient_scan_tmr = 0;
#if defined(BACNET_TIME_MASTER)
    BACNET_DATE_TIME bdatetime;
#endif
#if defined(BAC_UCI)
    int uciId = 0;
    struct uci_context *ctx;
#endif
    int argi = 0;
    const char *filename = NULL;

    filename = filename_remove_path(argv[0]);
    for (argi = 1; argi < argc; argi++) {
        if (strcmp(argv[argi], "--help") == 0) {
            print_usage(filename);
            print_help(filename);
            return 0;
        }
        if (strcmp(argv[argi], "--version") == 0) {
            printf("%s %s\n", filename, BACNET_VERSION_TEXT);
            printf("Copyright (C) 2014 by Steve Karg and others.\n"
                "This is free software; see the source for copying conditions.\n"
                "There is NO warranty; not even for MERCHANTABILITY or\n"
                "FITNESS FOR A PARTICULAR PURPOSE.\n");
            return 0;
        }
    }
#if defined(BAC_UCI)
    ctx = ucix_init("bacnet_dev");
    if (!ctx)
        fprintf(stderr, "Failed to load config file bacnet_dev\n");
    uciId = ucix_get_option_int(ctx, "bacnet_dev", "0", "Id", 0);
    printf("ID: %i", uciId);
    if (uciId != 0) {
        Device_Set_Object_Instance_Number(uciId);
    } else {
#endif /* defined(BAC_UCI) */
        /* allow the device ID to be set */
        if (argc > 1) {
            Device_Set_Object_Instance_Number(strtol(argv[1], NULL, 0));
        }
        if (argc > 2) {
            Device_Object_Name_ANSI_Init(argv[2]);
        }
#if defined(BAC_UCI)
    }
    ucix_cleanup(ctx);
#endif /* defined(BAC_UCI) */

    printf("BACnet Server Demo\n" "BACnet Stack Version %s\n"
        "BACnet Device ID: %u\n" "Max APDU: %d\n", BACnet_Version,
        Device_Object_Instance_Number(), MAX_APDU);
    /* load any static address bindings to show up
       in our device bindings list */
    address_init();
    Init_Service_Handlers();
    dlenv_init();
    atexit(datalink_cleanup);
    /* configure the timeout values */
    last_seconds = time(NULL);
    /* broadcast an I-Am on startup */
    Send_I_Am(&Handler_Transmit_Buffer[0]);
    /* loop forever */
    for (;;) {
        /* input */
        current_seconds = time(NULL);

        /* returns 0 bytes on timeout */
        pdu_len = datalink_receive(&src, &Rx_Buf[0], MAX_MPDU, timeout);

        /* process */
        if (pdu_len) {
#if MEASURE_SERVER
        	struct timespec t1, t2, clock_resolution;
        	long long elapsedTime;
        	clock_getres(CLOCK_REALTIME, &clock_resolution);
        	clock_gettime(CLOCK_REALTIME, &t1);
#endif
        	npdu_handler(&src, &Rx_Buf[0], pdu_len);
#if MEASURE_SERVER
        	clock_gettime(CLOCK_REALTIME, &t2);
        	elapsedTime = ((t2.tv_sec * 1000000000L) + t2.tv_nsec)
          	              - ((t1.tv_sec * 1000000000L) + t1.tv_nsec);
        	// determine the PDU type here again not to influence the measurement
        	BACNET_ADDRESS dest = { 0 };
       	    BACNET_NPDU_DATA npdu_data = { 0 };
       	    uint8_t  service_choice;
            if (Rx_Buf[0] == BACNET_PROTOCOL_VERSION) {
                int offset = npdu_decode(&Rx_Buf[0], &dest, &src, &npdu_data);
                if (npdu_data.network_layer_message) {
                    /*FIXME: Only secured Network Layer Message Types handled*/
                	if(npdu_data.network_message_type >= NETWORK_MESSAGE_CHALLENGE_REQUEST &&
                	   npdu_data.network_message_type <= NETWORK_MESSAGE_SET_MASTER_KEY) {
                		FILE *file;
                		if( (file = fopen("server.dat", "a")) == NULL){
                			printf("File not found!\n");
                			return 0;
                		} else{
                			BACNET_SECURITY_WRAPPER w;
                			uint8_t test[MAX_APDU];
                			w.service_data = test;
                			uint32_t len_remaining = pdu_len - offset;
                			decode_security_wrapper_safe(1, &Rx_Buf[offset], len_remaining, &w);
                			switch (w.service_data[2]) {
                   			case PDU_TYPE_CONFIRMED_SERVICE_REQUEST:
                				service_choice = w.service_data[5];
                			    switch(service_choice) {
                				case SERVICE_CONFIRMED_READ_PROPERTY:
                					fprintf(file, "ReadProperty %lld\n", elapsedTime);
                					break;
                				case SERVICE_CONFIRMED_WRITE_PROPERTY:
                					fprintf(file, "WriteProperty %lld\n", elapsedTime);
                					break;
                				case SERVICE_CONFIRMED_ATOMIC_READ_FILE:
                					fprintf(file, "ReadFile %lld\n", elapsedTime);
                					break;
                				case SERVICE_CONFIRMED_ATOMIC_WRITE_FILE:
                					fprintf(file, "WriteFileFile %lld\n", elapsedTime);
                					break;
                				default:
                					break;
                				}
                				break;
                			case PDU_TYPE_UNCONFIRMED_SERVICE_REQUEST:
                				service_choice = w.service_data[3];
                				switch (service_choice) {
                				case SERVICE_UNCONFIRMED_WHO_IS:
                					fprintf(file, "WhoIs %lld\n", elapsedTime);
                					break;
                				case SERVICE_UNCONFIRMED_WHO_HAS:
                					fprintf(file, "WhoHas %lld\n", elapsedTime);
                					break;
                				case SERVICE_UNCONFIRMED_I_AM:
                					fprintf(file, "IAm %lld\n", elapsedTime);
                					break;
                				default:
                					break;
                				}
                				break;
                			case PDU_TYPE_SIMPLE_ACK:
                				fprintf(file, "SimpleACK %lld\n", elapsedTime);
                				break;
                			case PDU_TYPE_COMPLEX_ACK:
                				fprintf(file, "ComplexACK %lld\n", elapsedTime);
                				break;
                			default:
                				break;
                			}
                			fclose(file);
                		}
                	}
                } else if ((offset > 0) && (offset <= pdu_len)) {
                	FILE *file;
                	if( (file = fopen("server.dat", "a")) == NULL){
                		printf("File not found!\n");
                		return 0;
                	} else{
                		switch (Rx_Buf[offset] & 0xF0) {
                		case PDU_TYPE_CONFIRMED_SERVICE_REQUEST:
                			service_choice = Rx_Buf[offset + 3];
                 			switch(service_choice) {
                 			case SERVICE_CONFIRMED_READ_PROPERTY:
                 				fprintf(file, "ReadProperty %lld\n", elapsedTime);
                				break;
                			case SERVICE_CONFIRMED_WRITE_PROPERTY:
                				fprintf(file, "WriteProperty %lld\n", elapsedTime);
                				break;
                			case SERVICE_CONFIRMED_ATOMIC_READ_FILE:
                				fprintf(file, "ReadFile %lld\n", elapsedTime);
                				break;
                			case SERVICE_CONFIRMED_ATOMIC_WRITE_FILE:
                				fprintf(file, "WriteFileFile %lld\n", elapsedTime);
                				break;
                			default:
                				break;
                			}
                 			break;
                		case PDU_TYPE_UNCONFIRMED_SERVICE_REQUEST:
                			service_choice = Rx_Buf[offset + 1];
                			switch (service_choice) {
                			case SERVICE_UNCONFIRMED_WHO_IS:
                				fprintf(file, "WhoIs %lld\n", elapsedTime);
                				break;
                			case SERVICE_UNCONFIRMED_WHO_HAS:
                				fprintf(file, "WhoHas %lld\n", elapsedTime);
                				break;
                			case SERVICE_UNCONFIRMED_I_AM:
                				fprintf(file, "IAm %lld\n", elapsedTime);
                				break;
                			default:
                				break;
                			}
                			break;
                		case PDU_TYPE_SIMPLE_ACK:
                			fprintf(file, "SimpleACK %lld\n", elapsedTime);
                			break;
                		case PDU_TYPE_COMPLEX_ACK:
                			fprintf(file, "ComplexACK %lld\n", elapsedTime);
                			break;
                		default:
                			break;
                		}
                		fclose(file);
                	}
                }
            }
#endif
  	  }
        /* at least one second has passed */
        elapsed_seconds = (uint32_t) (current_seconds - last_seconds);
        if (elapsed_seconds) {
            last_seconds = current_seconds;
            dcc_timer_seconds(elapsed_seconds);
#if defined(BACDL_BIP) && BBMD_ENABLED
            bvlc_maintenance_timer(elapsed_seconds);
#endif
            dlenv_maintenance_timer(elapsed_seconds);
            Load_Control_State_Machine_Handler();
            elapsed_milliseconds = elapsed_seconds * 1000;
            handler_cov_timer_seconds(elapsed_seconds);
            tsm_timer_milliseconds(elapsed_milliseconds);
            trend_log_timer(elapsed_seconds);
#if defined(INTRINSIC_REPORTING)
            Device_local_reporting();
#endif
#if defined(BACNET_TIME_MASTER)
            Device_getCurrentDateTime(&bdatetime);
            handler_timesync_task(&bdatetime);
#endif
        }
        handler_cov_task();
        /* scan cache address */
        address_binding_tmr += elapsed_seconds;
        if (address_binding_tmr >= 60) {
            address_cache_timer(address_binding_tmr);
            address_binding_tmr = 0;
        }
#if defined(INTRINSIC_REPORTING)
        /* try to find addresses of recipients */
        recipient_scan_tmr += elapsed_seconds;
        if (recipient_scan_tmr >= NC_RESCAN_RECIPIENTS_SECS) {
            Notification_Class_find_recipient();
            recipient_scan_tmr = 0;
        }
#endif
        /* output */

        /* blink LEDs, Turn on or off outputs, etc */
    }

    return 0;
}

/* @} */

/* End group ServerDemo */
