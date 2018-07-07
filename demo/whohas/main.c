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

/* command line tool that sends a BACnet service, and displays the reply */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>       /* for time */
#include <errno.h>
#include "bactext.h"
#include "iam.h"
#include "arf.h"
#include "tsm.h"
#include "address.h"
#include "config.h"
#include "bacdef.h"
#include "npdu.h"
#include "apdu.h"
#include "device.h"
#include "net.h"
#include "datalink.h"
#include "whohas.h"
/* some demo stuff needed */
#include "filename.h"
#include "handlers.h"
#include "client.h"
#include "txbuf.h"
#include "dlenv.h"

<<<<<<< HEAD
/* buffer used for receive */
static uint8_t Rx_Buf[MAX_MPDU] = { 0 };

/* global variables used in this file */
static BACNET_OBJECT_TYPE Target_Object_Type = MAX_BACNET_OBJECT_TYPE;
static uint32_t Target_Object_Instance = BACNET_MAX_INSTANCE;
static char *Target_Object_Name = NULL;
static int32_t Target_Object_Instance_Min = -1;
static int32_t Target_Object_Instance_Max = -1;

static bool Error_Detected = false;

void MyAbortHandler(
    BACNET_ADDRESS * src,
    uint8_t invoke_id,
    uint8_t abort_reason,
    bool server)
{
    /* FIXME: verify src and invoke id */
    (void) src;
    (void) invoke_id;
    (void) server;
    printf("BACnet Abort: %s\r\n", bactext_abort_reason_name(abort_reason));
    Error_Detected = true;
}

void MyRejectHandler(
    BACNET_ADDRESS * src,
    uint8_t invoke_id,
    uint8_t reject_reason)
{
    /* FIXME: verify src and invoke id */
    (void) src;
    (void) invoke_id;
    printf("BACnet Reject: %s\r\n", bactext_reject_reason_name(reject_reason));
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
    apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_I_HAVE, handler_i_have);
    /* handle any errors coming back */
    apdu_set_abort_handler(MyAbortHandler);
    apdu_set_reject_handler(MyRejectHandler);
}

static void print_usage(
    char *filename)
{
    printf("Usage: %s [device-instance-min device-instance-min] "
        "<object-type object-instance | object-name> [--help]\r\n", filename);
}

static void print_help(
    char *filename)
{
    print_usage(filename);
    printf("Send BACnet WhoHas request to devices, \r\n"
        "and wait %u milliseconds (BACNET_APDU_TIMEOUT) for responses.\r\n"
        "The device-instance-min or max can be 0 to %d.\r\n" "\r\n"
        "Use either:\r\n" "The object-type can be 0 to %d.\r\n"
        "The object-instance can be 0 to %d.\r\n" "or:\r\n"
        "The object-name can be any string of characters.\r\n",
        BACNET_MAX_INSTANCE, (unsigned) apdu_timeout(), BACNET_MAX_OBJECT,
        BACNET_MAX_INSTANCE);
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
    time_t elapsed_seconds = 0;
    time_t last_seconds = 0;
    time_t current_seconds = 0;
    time_t timeout_seconds = 0;
    int argi = 0;
    bool by_name = false;

    if (argc < 2) {
        print_usage(filename_remove_path(argv[0]));
        return 0;
    }
    /* print help if requested */
    for (argi = 1; argi < argc; argi++) {
        if (strcmp(argv[argi], "--help") == 0) {
            print_help(filename_remove_path(argv[0]));
            return 0;
        }
    }
    /* decode the command line parameters */
    if (argc < 3) {
        /* bacwh "name" */
        Target_Object_Instance_Min = Target_Object_Instance_Max = -1;
        Target_Object_Name = argv[1];
        by_name = true;
    } else if (argc < 4) {
        /* bacwh 8 1234 */
        Target_Object_Instance_Min = Target_Object_Instance_Max = -1;
        Target_Object_Type = strtol(argv[1], NULL, 0);
        Target_Object_Instance = strtol(argv[2], NULL, 0);
    } else if (argc < 5) {
        /* bacwh 0 4194303 "name" */
        Target_Object_Instance_Min = strtol(argv[1], NULL, 0);
        Target_Object_Instance_Max = strtol(argv[2], NULL, 0);
        Target_Object_Name = argv[3];
        by_name = true;
    } else if (argc < 6) {
        /* bacwh 0 4194303 8 1234 */
        Target_Object_Instance_Min = strtol(argv[1], NULL, 0);
        Target_Object_Instance_Max = strtol(argv[2], NULL, 0);
        Target_Object_Type = strtol(argv[3], NULL, 0);
        Target_Object_Instance = strtol(argv[4], NULL, 0);
    } else {
        print_usage(filename_remove_path(argv[0]));
        return 1;
    }
    if (by_name) {
        if (Target_Object_Name) {
            if (Target_Object_Name[0] == 0) {
                fprintf(stderr,
                    "object-name must be at least 1 character.\r\n");
                return 1;
            }
        } else {
            fprintf(stderr, "missing object-name value.\r\n");
            return 1;
        }
    } else {
        if (Target_Object_Instance > BACNET_MAX_INSTANCE) {
            fprintf(stderr, "object-instance=%u - it must be less than %u\r\n",
                Target_Object_Instance, BACNET_MAX_INSTANCE + 1);
            return 1;
        }
        if (Target_Object_Type > BACNET_MAX_OBJECT) {
            fprintf(stderr, "object-type=%u - it must be less than %u\r\n",
                Target_Object_Type, BACNET_MAX_OBJECT + 1);
            return 1;
        }
    }
    if (Target_Object_Instance_Min > BACNET_MAX_INSTANCE) {
        fprintf(stderr, "object-instance-min=%u - it must be less than %u\r\n",
            Target_Object_Instance_Min, BACNET_MAX_INSTANCE + 1);
        return 1;
    }
    if (Target_Object_Instance_Max > BACNET_MAX_INSTANCE) {
        fprintf(stderr, "object-instance-max=%u - it must be less than %u\r\n",
            Target_Object_Instance_Max, BACNET_MAX_INSTANCE + 1);
        return 1;
    }
    /* setup my info */
    Device_Set_Object_Instance_Number(BACNET_MAX_INSTANCE);
    Init_Service_Handlers();
    dlenv_init();
    atexit(datalink_cleanup);
    /* configure the timeout values */
    last_seconds = time(NULL);
    timeout_seconds = apdu_timeout() / 1000;
    /* send the request */
    if (by_name) {
        Send_WhoHas_Name(Target_Object_Instance_Min,
            Target_Object_Instance_Max, Target_Object_Name);
    } else {
        Send_WhoHas_Object(Target_Object_Instance_Min,
            Target_Object_Instance_Max, Target_Object_Type,
            Target_Object_Instance);
    }
    /* loop forever */
    for (;;) {
        /* increment timer - exit if timed out */
        current_seconds = time(NULL);
        /* returns 0 bytes on timeout */
        pdu_len = datalink_receive(&src, &Rx_Buf[0], MAX_MPDU, timeout);
        /* process */
        if (pdu_len) {
            npdu_handler(&src, &Rx_Buf[0], pdu_len);
        }
        if (Error_Detected)
            break;
        /* increment timer - exit if timed out */
        elapsed_seconds += (current_seconds - last_seconds);
        if (elapsed_seconds > timeout_seconds)
            break;
        /* keep track of time for next check */
        last_seconds = current_seconds;
    }

=======
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

/* global variables used in this file */
static BACNET_OBJECT_TYPE Target_Object_Type = MAX_BACNET_OBJECT_TYPE;
static uint32_t Target_Object_Instance = BACNET_MAX_INSTANCE;
static char *Target_Object_Name = NULL;
static int32_t Target_Object_Instance_Min = -1;
static int32_t Target_Object_Instance_Max = -1;

static bool Error_Detected = false;

void MyAbortHandler(
    BACNET_ADDRESS * src,
    uint8_t invoke_id,
    uint8_t abort_reason,
    bool server)
{
    /* FIXME: verify src and invoke id */
    (void) src;
    (void) invoke_id;
    (void) server;
    printf("BACnet Abort: %s\r\n", bactext_abort_reason_name(abort_reason));
    Error_Detected = true;
}

void MyRejectHandler(
    BACNET_ADDRESS * src,
    uint8_t invoke_id,
    uint8_t reject_reason)
{
    /* FIXME: verify src and invoke id */
    (void) src;
    (void) invoke_id;
    printf("BACnet Reject: %s\r\n", bactext_reject_reason_name(reject_reason));
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
    apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_I_HAVE, handler_i_have);
    /* handle any errors coming back */
    apdu_set_abort_handler(MyAbortHandler);
    apdu_set_reject_handler(MyRejectHandler);
}

static void print_usage(
    char *filename)
{
    printf("Usage: %s [device-instance-min device-instance-min] "
        "<object-type object-instance | object-name> [--help]\r\n", filename);
}

static void print_help(
    char *filename)
{
    print_usage(filename);
    printf("Send BACnet WhoHas request to devices, \r\n"
        "and wait %u milliseconds (BACNET_APDU_TIMEOUT) for responses.\r\n"
        "The device-instance-min or max can be 0 to %d.\r\n" "\r\n"
        "Use either:\r\n" "The object-type can be 0 to %d.\r\n"
        "The object-instance can be 0 to %d.\r\n" "or:\r\n"
        "The object-name can be any string of characters.\r\n",
        BACNET_MAX_INSTANCE, (unsigned) apdu_timeout(), BACNET_MAX_OBJECT,
        BACNET_MAX_INSTANCE);
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
    time_t elapsed_seconds = 0;
    time_t last_seconds = 0;
    time_t current_seconds = 0;
    time_t timeout_seconds = 0;
    int argi = 0;
    bool by_name = false;

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

    if (argc < 2) {
        print_usage(filename_remove_path(argv[0]));
        return 0;
    }
    /* print help if requested */
    for (argi = 1; argi < argc; argi++) {
        if (strcmp(argv[argi], "--help") == 0) {
            print_help(filename_remove_path(argv[0]));
            return 0;
        }
    }
    /* decode the command line parameters */
    if (argc < 3) {
        /* bacwh "name" */
        Target_Object_Instance_Min = Target_Object_Instance_Max = -1;
        Target_Object_Name = argv[1];
        by_name = true;
    } else if (argc < 4) {
        /* bacwh 8 1234 */
        Target_Object_Instance_Min = Target_Object_Instance_Max = -1;
        Target_Object_Type = strtol(argv[1], NULL, 0);
        Target_Object_Instance = strtol(argv[2], NULL, 0);
    } else if (argc < 5) {
        /* bacwh 0 4194303 "name" */
        Target_Object_Instance_Min = strtol(argv[1], NULL, 0);
        Target_Object_Instance_Max = strtol(argv[2], NULL, 0);
        Target_Object_Name = argv[3];
        by_name = true;
    } else if (argc < 6) {
        /* bacwh 0 4194303 8 1234 */
        Target_Object_Instance_Min = strtol(argv[1], NULL, 0);
        Target_Object_Instance_Max = strtol(argv[2], NULL, 0);
        Target_Object_Type = strtol(argv[3], NULL, 0);
        Target_Object_Instance = strtol(argv[4], NULL, 0);
    } else {
        print_usage(filename_remove_path(argv[0]));
        return 1;
    }
    if (by_name) {
        if (Target_Object_Name) {
            if (Target_Object_Name[0] == 0) {
                fprintf(stderr,
                    "object-name must be at least 1 character.\r\n");
                return 1;
            }
        } else {
            fprintf(stderr, "missing object-name value.\r\n");
            return 1;
        }
    } else {
        if (Target_Object_Instance > BACNET_MAX_INSTANCE) {
            fprintf(stderr, "object-instance=%u - it must be less than %u\r\n",
                Target_Object_Instance, BACNET_MAX_INSTANCE + 1);
            return 1;
        }
        if (Target_Object_Type > BACNET_MAX_OBJECT) {
            fprintf(stderr, "object-type=%u - it must be less than %u\r\n",
                Target_Object_Type, BACNET_MAX_OBJECT + 1);
            return 1;
        }
    }
    if (Target_Object_Instance_Min > BACNET_MAX_INSTANCE) {
        fprintf(stderr, "object-instance-min=%u - it must be less than %u\r\n",
            Target_Object_Instance_Min, BACNET_MAX_INSTANCE + 1);
        return 1;
    }
    if (Target_Object_Instance_Max > BACNET_MAX_INSTANCE) {
        fprintf(stderr, "object-instance-max=%u - it must be less than %u\r\n",
            Target_Object_Instance_Max, BACNET_MAX_INSTANCE + 1);
        return 1;
    }
    /* setup my info */
    Device_Set_Object_Instance_Number(BACNET_MAX_INSTANCE);
    Init_Service_Handlers();
    dlenv_init();
    atexit(datalink_cleanup);
    /* configure the timeout values */
    last_seconds = time(NULL);
    timeout_seconds = apdu_timeout() / 1000;
    /* send the request */
    if (by_name) {
#if MEASURE_CLIENT
       struct timespec t1, t2, clock_resolution;
       long long elapsedTime;
       clock_getres(CLOCK_REALTIME, &clock_resolution);
       clock_gettime(CLOCK_REALTIME, &t1);
#endif
        Send_WhoHas_Name(Target_Object_Instance_Min,
            Target_Object_Instance_Max, Target_Object_Name);
#if MEASURE_CLIENT
  	  clock_gettime(CLOCK_REALTIME, &t2);
  	  elapsedTime = ((t2.tv_sec * 1000000000L) + t2.tv_nsec)
          	              - ((t1.tv_sec * 1000000000L) + t1.tv_nsec);

  	  FILE *file;
      if( (file = fopen("wh.dat", "a")) == NULL){
       	printf("File not found!\n");
       	return 0;
       } else{
       	fprintf(file, "%lld\n", elapsedTime);
       	fclose(file);
       }
#endif
    } else {
#if MEASURE_CLIENT
       struct timespec t1, t2, clock_resolution;
       long long elapsedTime;
       clock_getres(CLOCK_REALTIME, &clock_resolution);
       clock_gettime(CLOCK_REALTIME, &t1);
#endif
    	Send_WhoHas_Object(Target_Object_Instance_Min,
            Target_Object_Instance_Max, Target_Object_Type,
            Target_Object_Instance);
#if MEASURE_CLIENT
  	  clock_gettime(CLOCK_REALTIME, &t2);
  	  elapsedTime = ((t2.tv_sec * 1000000000L) + t2.tv_nsec)
          	              - ((t1.tv_sec * 1000000000L) + t1.tv_nsec);
  	  FILE *file;
      if( (file = fopen("wh.dat", "a")) == NULL){
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
        /* returns 0 bytes on timeout */
        pdu_len = datalink_receive(&src, &Rx_Buf[0], MAX_MPDU, timeout);
        /* process */
        if (pdu_len) {
            npdu_handler(&src, &Rx_Buf[0], pdu_len);
        }
        if (Error_Detected)
            break;
        /* increment timer - exit if timed out */
        elapsed_seconds += (current_seconds - last_seconds);
        if (elapsed_seconds > timeout_seconds)
            break;
        /* keep track of time for next check */
        last_seconds = current_seconds;
    }
>>>>>>> refs/heads/bacnet-sec
    return 0;
}
