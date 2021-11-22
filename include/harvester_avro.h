/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#ifndef _HARVESTER_AVRO_H
#define _HARVESTER_AVRO_H

#include <sys/time.h>
#include <wifi_hal.h>
#include <pthread.h>

struct associateddevicedata
{
struct timeval timestamp;
char* sSidName;
char* bssid;
char* radioOperatingFrequencyBand; //Possible value 2.4Ghz and 5.0 Ghz
ULONG radioChannel;  // Possible Value between 1-11
ULONG numAssocDevices;
wifi_associated_dev_t* devicedata;

struct associateddevicedata *next;
};


struct neighboringapdata
{
struct timeval timestamp;
char* radioName;
char* radioOperatingFrequencyBand; //Possible value 2.4Ghz and 5.0 Ghz
ULONG radioChannel;  // Possible Value between 1-11
ULONG numNeibouringAP;
wifi_neighbor_ap2_t* napdata;

struct neighboringapdata *next;
};


struct radiotrafficdata
{
struct timeval timestamp;
char* radioBssid;
BOOL  enabled;
char* radioOperatingFrequencyBand; //Possible value 2.4Ghz and 5.0 Ghz
ULONG radioChannel;  // Possible Value between 1-11
char* radiOperatingChannelBandwidth;
wifi_radioTrafficStats2_t* rtdata;
};

extern void harvester_report_associateddevices(struct associateddevicedata *head, char* ServiceType);
extern void harvester_report_neighboringap(struct neighboringapdata *head);
extern void harvester_report_radiotraffic(struct radiotrafficdata *head);

#endif /* !_HARVESTER_AVRO_H */
