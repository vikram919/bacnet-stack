/*************************************************************************
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

/* command line tool that sends a BACnet service, and displays the reply */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>       /* for time */

#define PRINT_ENABLED 1

#include "bacdef.h"
#include "config.h"
#include "bactext.h"
#include "bacerror.h"
#include "iam.h"
#include "arf.h"
#include "tsm.h"
#include "address.h"
#include "npdu.h"
#include "apdu.h"
#include "device.h"
#include "net.h"
#include "datalink.h"
#include "whois.h"
#include "version.h"
/* some demo stuff needed */
#include "filename.h"
#include "handlers.h"
#include "client.h"
#include "txbuf.h"
#include "dlenv.h"

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

/* buffer used for receive */
static uint8_t Rx_Buf[MAX_MPDU] = { 0 };

/* converted command line arguments */
static uint32_t Target_Device_Object_Instance = BACNET_MAX_INSTANCE;
static uint32_t Target_Object_Instance = BACNET_MAX_INSTANCE;
static BACNET_OBJECT_TYPE Target_Object_Type = OBJECT_ANALOG_INPUT;
static BACNET_PROPERTY_ID Target_Object_Property = PROP_ACKED_TRANSITIONS;
static int32_t Target_Object_Index = BACNET_ARRAY_ALL;
/* the invoke id is needed to filter incoming messages */
static uint8_t Request_Invoke_ID = 0;
static BACNET_ADDRESS Target_Address;
static bool Error_Detected = false;

static void MyErrorHandler(
    BACNET_ADDRESS * src,
    uint8_t invoke_id,
    BACNET_ERROR_CLASS error_class,
    BACNET_ERROR_CODE error_code)
{
    if (address_match(&Target_Address, src) &&
        (invoke_id == Request_Invoke_ID)) {
        printf("BACnet Error: %s: %s\n",
            bactext_error_class_name((int) error_class),
            bactext_error_code_name((int) error_code));
        Error_Detected = true;
    }
}

void MyAbortHandler(
    BACNET_ADDRESS * src,
    uint8_t invoke_id,
    uint8_t abort_reason,
    bool server)
{
    (void) server;
    if (address_match(&Target_Address, src) &&
        (invoke_id == Request_Invoke_ID)) {
        printf("BACnet Abort: %s\n",
            bactext_abort_reason_name((int) abort_reason));
        Error_Detected = true;
    }
}

void MyRejectHandler(
    BACNET_ADDRESS * src,
    uint8_t invoke_id,
    uint8_t reject_reason)
{
    if (address_match(&Target_Address, src) &&
        (invoke_id == Request_Invoke_ID)) {
        printf("BACnet Reject: %s\n",
            bactext_reject_reason_name((int) reject_reason));
        Error_Detected = true;
    }
}

/** Handler for a ReadProperty ACK.
 * @ingroup DSRP
 * Doesn't actually do anything, except, for debugging, to
 * print out the ACK data of a matching request.
 *
 * @param service_request [in] The contents of the service request.
 * @param service_len [in] The length of the service_request.
 * @param src [in] BACNET_ADDRESS of the source of the message
 * @param service_data [in] The BACNET_CONFIRMED_SERVICE_DATA information
 *                          decoded from the APDU header of this message.
 */
void My_Read_Property_Ack_Handler(
    uint8_t * service_request,
    uint16_t service_len,
    BACNET_ADDRESS * src,
    BACNET_CONFIRMED_SERVICE_ACK_DATA * service_data)
{
    int len = 0;
    BACNET_READ_PROPERTY_DATA data;

    if (address_match(&Target_Address, src) &&
        (service_data->invoke_id == Request_Invoke_ID)) {
        len =
            rp_ack_decode_service_request(service_request, service_len, &data);
        if (len < 0) {
            printf("<decode failed!>\n");
        } else {
            rp_ack_print_data(&data);
        }
    }
}

static void Init_Service_Handlers(
    void)
{
    Device_Init(NULL);
    /* we need to handle who-is
       to support dynamic device binding to us */
    apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_WHO_IS, handler_who_is);
    /* handle i-am to support binding to other devices */
    apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_I_AM, handler_i_am_bind);
    /* set the handler for all the services we don't implement
       It is required to send the proper reject message... */
    apdu_set_unrecognized_service_handler_handler
        (handler_unrecognized_service);
    /* we must implement read property - it's required! */
    apdu_set_confirmed_handler(SERVICE_CONFIRMED_READ_PROPERTY,
        handler_read_property);
    /* handle the data coming back from confirmed requests */
    apdu_set_confirmed_ack_handler(SERVICE_CONFIRMED_READ_PROPERTY,
        My_Read_Property_Ack_Handler);
    /* handle any errors coming back */
    apdu_set_error_handler(SERVICE_CONFIRMED_READ_PROPERTY, MyErrorHandler);
    apdu_set_abort_handler(MyAbortHandler);
    apdu_set_reject_handler(MyRejectHandler);
}

static void print_usage(char *filename)
{
    printf("Usage: %s device-instance object-type object-instance "
        "property [index]\n", filename);
    printf("       [--dnet][--dadr][--mac]\n");
    printf("       [--version][--help]\n");
}

static void print_help(char *filename)
{
    printf("Read a property from an object in a BACnet device\n"
        "and print the value.\n");
    printf("--mac A\n"
        "Optional BACnet mac address."
        "Valid ranges are from 00 to FF (hex) for MS/TP or ARCNET,\n"
        "or an IP string with optional port number like 10.1.2.3:47808\n"
        "or an Ethernet MAC in hex like 00:21:70:7e:32:bb\n"
        "\n"
        "--dnet N\n"
        "Optional BACnet network number N for directed requests.\n"
        "Valid range is from 0 to 65535 where 0 is the local connection\n"
        "and 65535 is network broadcast.\n"
        "\n"
        "--dadr A\n"
        "Optional BACnet mac address on the destination BACnet network number.\n"
        "Valid ranges are from 00 to FF (hex) for MS/TP or ARCNET,\n"
        "or an IP string with optional port number like 10.1.2.3:47808\n"
        "or an Ethernet MAC in hex like 00:21:70:7e:32:bb\n"
        "\n");
    printf("device-instance:\n"
        "BACnet Device Object Instance number that you are\n"
        "trying to communicate to.  This number will be used\n"
        "to try and bind with the device using Who-Is and\n"
        "I-Am services.  For example, if you were reading\n"
        "Device Object 123, the device-instance would be 123.\n"
        "\nobject-type:\n"
        "The object type is the integer value of the enumeration\n"
        "BACNET_OBJECT_TYPE in bacenum.h.  It is the object\n"
        "that you are reading.  For example if you were\n"
        "reading Analog Output 2, the object-type would be 1.\n"
        "\nobject-instance:\n"
        "This is the object instance number of the object that\n"
        "you are reading.  For example, if you were reading\n"
        "Analog Output 2, the object-instance would be 2.\n"
        "\nproperty:\n"
        "The property is an integer value of the enumeration\n"
        "BACNET_PROPERTY_ID in bacenum.h.  It is the property\n"
        "you are reading.  For example, if you were reading the\n"
        "Present Value property, use 85 as the property.\n"
        "\nindex:\n"
        "This integer parameter is the index number of an array.\n"
        "If the property is an array, individual elements can\n"
        "be read.  If this parameter is missing and the property\n"
        "is an array, the entire array will be read.\n"
        "\nExample:\n"
        "If you want read the Present-Value of Analog Output 101\n"
        "in Device 123, you could send the following command:\n"
        "%s 123 1 101 85\n"
        "If you want read the Priority-Array of Analog Output 101\n"
        "in Device 123, you could send the following command:\n"
        "%s 123 1 101 87\n", filename, filename);
}

int main(
    int argc,
    char *argv[])
{
    BACNET_ADDRESS src = {
        0
    };  /* address where message came from */
    uint16_t pdu_len = 0;
    unsigned timeout = 100;     /* milliseconds */
    unsigned max_apdu = 0;
    time_t elapsed_seconds = 0;
    time_t last_seconds = 0;
    time_t current_seconds = 0;
    time_t timeout_seconds = 0;
    bool found = false;
    long dnet = -1;
    BACNET_MAC_ADDRESS mac = { 0 };
    BACNET_MAC_ADDRESS adr = { 0 };
    BACNET_ADDRESS dest = { 0 };
    bool specific_address = false;
    int argi = 0;
    unsigned int target_args = 0;
    char *filename = NULL;

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
    filename = filename_remove_path(argv[0]);
    for (argi = 1; argi < argc; argi++) {
        if (strcmp(argv[argi], "--help") == 0) {
            print_usage(filename);
            print_help(filename);
            return 0;
        }
        if (strcmp(argv[argi], "--version") == 0) {
            printf("%s %s\n", filename, BACNET_VERSION_TEXT);
            printf("Copyright (C) 2015 by Steve Karg and others.\n"
                "This is free software; see the source for copying conditions.\n"
                "There is NO warranty; not even for MERCHANTABILITY or\n"
                "FITNESS FOR A PARTICULAR PURPOSE.\n");
            return 0;
        }
        if (strcmp(argv[argi], "--mac") == 0) {
            if (++argi < argc) {
                if (address_mac_from_ascii(&mac, argv[argi])) {
                    specific_address = true;
                }
            }
        } else if (strcmp(argv[argi], "--dnet") == 0) {
            if (++argi < argc) {
                dnet = strtol(argv[argi], NULL, 0);
                if ((dnet >= 0) && (dnet <= BACNET_BROADCAST_NETWORK)) {
                    specific_address = true;
                }
            }
        } else if (strcmp(argv[argi], "--dadr") == 0) {
            if (++argi < argc) {
                if (address_mac_from_ascii(&adr, argv[argi])) {
                    specific_address = true;
                }
            }
        } else {
            if (target_args == 0) {
                Target_Device_Object_Instance = strtol(argv[argi], NULL, 0);
                target_args++;
            } else if (target_args == 1) {
                Target_Object_Type = strtol(argv[argi], NULL, 0);
                target_args++;
            } else if (target_args == 2) {
                Target_Object_Instance = strtol(argv[argi], NULL, 0);
                target_args++;
            } else if (target_args == 3) {
                Target_Object_Property = strtol(argv[argi], NULL, 0);
                target_args++;
            } else if (target_args == 4) {
                Target_Object_Index = strtol(argv[argi], NULL, 0);
                target_args++;
            } else {
                print_usage(filename);
                return 1;
            }
        }
    }
    if (target_args < 4) {
        print_usage(filename);
        return 0;
    }
    if (Target_Device_Object_Instance > BACNET_MAX_INSTANCE) {
        fprintf(stderr, "device-instance=%u - it must be less than %u\n",
            Target_Device_Object_Instance, BACNET_MAX_INSTANCE);
        return 1;
    }
    address_init();
    if (specific_address) {
        if (adr.len && mac.len) {
            memcpy(&dest.mac[0], &mac.adr[0], mac.len);
            dest.mac_len = mac.len;
            memcpy(&dest.adr[0], &adr.adr[0], adr.len);
            dest.len = adr.len;
            if ((dnet >= 0) && (dnet <= BACNET_BROADCAST_NETWORK)) {
                dest.net = dnet;
            } else {
                dest.net = BACNET_BROADCAST_NETWORK;
            }
        } else if (mac.len) {
            memcpy(&dest.mac[0], &mac.adr[0], mac.len);
            dest.mac_len = mac.len;
            dest.len = 0;
            if ((dnet >= 0) && (dnet <= BACNET_BROADCAST_NETWORK)) {
                dest.net = dnet;
            } else {
                dest.net = 0;
            }
        } else {
            if ((dnet >= 0) && (dnet <= BACNET_BROADCAST_NETWORK)) {
                dest.net = dnet;
            } else {
                dest.net = BACNET_BROADCAST_NETWORK;
            }
            dest.mac_len = 0;
            dest.len = 0;
        }
        address_add(Target_Device_Object_Instance, MAX_APDU, &dest);
    }
    /* setup my info */
    Device_Set_Object_Instance_Number(BACNET_MAX_INSTANCE);
    Init_Service_Handlers();
    dlenv_init();
    atexit(datalink_cleanup);
    /* configure the timeout values */
    last_seconds = time(NULL);
    timeout_seconds = (apdu_timeout() / 1000) * apdu_retries();
    /* try to bind with the device */
    found =
        address_bind_request(Target_Device_Object_Instance, &max_apdu,
        &Target_Address);
    if (!found) {
#if MEASURE_CLIENT
       struct timespec t1, t2, clock_resolution;
       long long elapsedTime;
       clock_getres(CLOCK_REALTIME, &clock_resolution);
       clock_gettime(CLOCK_REALTIME, &t1);
#endif
        Send_WhoIs(Target_Device_Object_Instance,
            Target_Device_Object_Instance);
#if MEASURE_CLIENT
  	  clock_gettime(CLOCK_REALTIME, &t2);
  	  elapsedTime = ((t2.tv_sec * 1000000000L) + t2.tv_nsec)
          	              - ((t1.tv_sec * 1000000000L) + t1.tv_nsec);

  	  FILE *file;
      if( (file = fopen("wi.dat", "a")) == NULL){
       	printf("File not found!\n");
       	return 0;
       } else{
       	fprintf(file, "%lld\n", elapsedTime);
       	fclose(file);
       }
#endif
    }
    /* loop forever */
    for (;;) {
        /* increment timer - exit if timed out */
        current_seconds = time(NULL);

        /* at least one second has passed */
        if (current_seconds != last_seconds)
            tsm_timer_milliseconds((uint16_t) ((current_seconds -
                        last_seconds) * 1000));
        if (Error_Detected)
            break;
        /* wait until the device is bound, or timeout and quit */
        if (!found) {
            found =
                address_bind_request(Target_Device_Object_Instance, &max_apdu,
                &Target_Address);
        }
        if (found) {
            if (Request_Invoke_ID == 0) {
#if MEASURE_CLIENT
       struct timespec t1, t2, clock_resolution;
       long long elapsedTime;
       clock_getres(CLOCK_REALTIME, &clock_resolution);
       clock_gettime(CLOCK_REALTIME, &t1);
#endif
                Request_Invoke_ID =
                    Send_Read_Property_Request(Target_Device_Object_Instance,
                    Target_Object_Type, Target_Object_Instance,
                    Target_Object_Property, Target_Object_Index);
#if MEASURE_CLIENT
  	  clock_gettime(CLOCK_REALTIME, &t2);
  	  elapsedTime = ((t2.tv_sec * 1000000000L) + t2.tv_nsec)
          	              - ((t1.tv_sec * 1000000000L) + t1.tv_nsec);

  	  FILE *file;
      if( (file = fopen("rp.dat", "a")) == NULL){
       	printf("File not found!\n");
       	return 0;
       } else{
       	fprintf(file, "%lld\n", elapsedTime);
       	fclose(file);
       }
#endif
            } else if (tsm_invoke_id_free(Request_Invoke_ID))
                break;
            else if (tsm_invoke_id_failed(Request_Invoke_ID)) {
                fprintf(stderr, "\rError: TSM Timeout!\n");
                tsm_free_invoke_id(Request_Invoke_ID);
                Error_Detected = true;
                /* try again or abort? */
                break;
            }
        } else {
            /* increment timer - exit if timed out */
            elapsed_seconds += (current_seconds - last_seconds);
            if (elapsed_seconds > timeout_seconds) {
                printf("\rError: APDU Timeout!\n");
                Error_Detected = true;
                break;
            }
        }

        /* returns 0 bytes on timeout */
        pdu_len = datalink_receive(&src, &Rx_Buf[0], MAX_MPDU, timeout);

        /* process */
        if (pdu_len) {
            npdu_handler(&src, &Rx_Buf[0], pdu_len);
        }

        /* keep track of time for next check */
        last_seconds = current_seconds;
    }

    if (Error_Detected)
        return 1;
    return 0;
}
