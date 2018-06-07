/**************************************************************************
*
* Copyright (C) 2016 Steve Karg <skarg@users.sourceforge.net>
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

/* command line tool that sends a BACnet service */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>       /* for time */
#include <errno.h>
#include "bactext.h"
#include "iam.h"
#include "address.h"
#include "config.h"
#include "bacdef.h"
#include "npdu.h"
#include "apdu.h"
#include "device.h"
#include "datalink.h"
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

// key
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

/* parsed command line parameters */
static uint32_t Target_Device_ID = BACNET_MAX_INSTANCE;
static uint16_t Target_Vendor_ID = BACNET_VENDOR_ID;
static unsigned int Target_Max_APDU = MAX_APDU;
static int Target_Segmentation = SEGMENTATION_NONE;
/* flag for signalling errors */
static bool Error_Detected = false;

void MyAbortHandler(
    BACNET_ADDRESS * src,
    uint8_t invoke_id,
    uint8_t abort_reason,
    bool server)
{
    (void) src;
    (void) invoke_id;
    (void) server;
    printf("BACnet Abort: %s\n", bactext_abort_reason_name(abort_reason));
    Error_Detected = true;
}

void MyRejectHandler(
    BACNET_ADDRESS * src,
    uint8_t invoke_id,
    uint8_t reject_reason)
{
    (void) src;
    (void) invoke_id;
    printf("BACnet Reject: %s\n", bactext_reject_reason_name(reject_reason));
    Error_Detected = true;
}

static void Init_Service_Handlers(
    void)
{
    Device_Init(NULL);
    /* we need to handle who-is
       to support dynamic device binding to us */
    apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_WHO_IS, handler_who_is);
    /* set the handler for all the services we don't implement
       It is required to send the proper reject message... */
    apdu_set_unrecognized_service_handler_handler
        (handler_unrecognized_service);
    /* we must implement read property - it's required! */
    apdu_set_confirmed_handler(SERVICE_CONFIRMED_READ_PROPERTY,
        handler_read_property);
    /* handle the reply (request) coming back */
    apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_I_AM, handler_i_am_add);
    /* handle any errors coming back */
    apdu_set_abort_handler(MyAbortHandler);
    apdu_set_reject_handler(MyRejectHandler);
}

static void print_usage(char *filename)
{
    printf("Usage: %s [device-instance vendor-id max-apdu segmentation]\n",
        filename);
    printf("       [--dnet][--dadr][--mac]\n");
    printf("       [--version][--help]\n");
}

static void print_help(char *filename)
{
    printf("Send BACnet I-Am message for a device.\n");
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
        "    BACnet device-ID 0..4194303\n"
        "vendor-id:\n"
        "    Vendor Identifier 0..65535\n"
        "max-apdu:\n"
        "    Maximum APDU size 50..65535\n"
        "segmentation:\n"
        "    BACnet Segmentation 0=both, 1=transmit, 2=receive, 3=none\n"
        "To send an I-Am message for instance=1234 vendor-id=260 max-apdu=480\n"
        "%s 1234 260 480\n",
        filename);
}

int main(
    int argc,
    char *argv[])
{
    long dnet = -1;
    BACNET_MAC_ADDRESS mac = { 0 };
    BACNET_MAC_ADDRESS adr = { 0 };
    BACNET_ADDRESS dest = { 0 };
    bool specific_address = false;
    int argi = 0;
    unsigned int target_args = 0;
    char *filename = NULL;

#if SECURITY_ENABLED
    // set master key
    BACNET_KEY_ENTRY key;
    //key.key_identifier = KIKN_GENERAL_NETWORK_ACCESS;
    key.key_identifier = KIKN_DEVICE_MASTER;
    key.key_len = sizeof(KEY);
    memcpy(key.key, &KEY, sizeof(KEY));

    BACNET_SET_MASTER_KEY master;

    memcpy(&master, &key, sizeof(BACNET_KEY_ENTRY));

    if(bacnet_master_key_set(&master) != SEC_RESP_SUCCESS)
    	return 0;

    initialize_security_wrapper();

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
            printf("Copyright (C) 2016 by Steve Karg and others.\n"
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
                Target_Device_ID = strtol(argv[argi], NULL, 0);
                target_args++;
            } else if (target_args == 1) {
                Target_Vendor_ID = strtol(argv[argi], NULL, 0);
                target_args++;
            } else if (target_args == 2) {
                Target_Max_APDU = strtol(argv[argi], NULL, 0);
                target_args++;
            } else if (target_args == 3) {
                Target_Segmentation = strtol(argv[argi], NULL, 0);
                target_args++;
            } else {
                print_usage(filename);
                return 1;
            }
        }
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
    }
    /* setup my info */
    Device_Set_Object_Instance_Number(BACNET_MAX_INSTANCE);
    Init_Service_Handlers();
    address_init();
    dlenv_init();
    atexit(datalink_cleanup);
    /* send the request */
    Send_I_Am_To_Network(&dest,
        Target_Device_ID,
        Target_Max_APDU,
        Target_Segmentation,
        Target_Vendor_ID);

    return 0;
}
