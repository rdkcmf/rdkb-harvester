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

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "harvester_neighboring_ap_ondemand.h"
#include "harvester_avro.h"
#include "ccsp_harvesterLog_wrapper.h"
#ifdef RDK_ONEWIFI
#include "harvester_rbus_api.h"

static bool neighWiFiDiag_ondemand_executed = false;
#endif

BOOL NAPOnDemandHarvesterStatus = FALSE;

#ifdef RDK_ONEWIFI
char tmp_buffer[72] = {'\0'};
#endif

static struct neighboringapdata *naphead = NULL;
static struct neighboringapdata *napcurr = NULL;

void* StartNeighboringAPOnDemandHarvesting(void* arg);

int _napondemandsyscmd(char *cmd, char *retBuf, int retBufSize);
int setNAPOnDemandCurrentTimeFromDmCli();
void add_to_nap_ondemand_list(char* radioIfName, ULONG numAPs, wifi_neighbor_ap2_t* neighborapdata, char* freqband, ULONG channel);
void print_nap_ondemand_list();
void delete_nap_ondemand_list();
int GetRadioNeighboringAPOnDemandData(int radioIndex, char* radioIfName);

#if !defined(UTC_ENABLE_ATOM) && !defined(_HUB4_PRODUCT_REQ_)
extern int getTimeOffsetFromUtc();
#endif

int SetNAPOnDemandHarvestingStatus(BOOL status)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s  Old[%d] New[%d] \n", __FUNCTION__, NAPOnDemandHarvesterStatus, status ));
    if (NAPOnDemandHarvesterStatus != status)
        NAPOnDemandHarvesterStatus = status;
    else
        return 0;

    if (NAPOnDemandHarvesterStatus)
    {
        pthread_t tid;

        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : Starting Thread to start NeighboringAP OnDemand Harvesting  \n", __FUNCTION__ ));

        if (pthread_create(&tid, NULL, StartNeighboringAPOnDemandHarvesting, NULL))
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : Failed to Start Thread to start NeighboringAP OnDemand Harvesting  \n", __FUNCTION__ ));
            return ANSC_STATUS_FAILURE;
        }
    }
    
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

    return 0;
}


BOOL GetNAPOnDemandHarvestingStatus()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT NAPOnDemandHarvesterStatus[%d] \n", __FUNCTION__, NAPOnDemandHarvesterStatus ));
    return NAPOnDemandHarvesterStatus;
}

int _napondemandsyscmd(char *cmd, char *retBuf, int retBufSize)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));

    FILE *f;
    char *ptr = retBuf;
    int bufSize = retBufSize, bufbytes = 0, readbytes = 0;

    if ((f = popen(cmd, "r")) == NULL) {
        CcspHarvesterTrace(("RDK_LOG_DEBUG, Harvester %s : popen %s error\n",__FUNCTION__, cmd));
        return -1;
    }

    while (!feof(f))
    {
        *ptr = 0;
        if (bufSize >= 128) {
            bufbytes = 128;
        } else {
            bufbytes = bufSize - 1;
        }

        if (fgets(ptr, bufbytes, f) == NULL)
           CcspHarvesterTrace(("RDK_LOG_DEBUG, Harvester %s : fgets error\n",__FUNCTION__));
        readbytes = strlen(ptr);
        if ( readbytes == 0)
            break;
        bufSize -= readbytes;
        ptr += readbytes;
    }
    pclose(f);
    retBuf[retBufSize - 1] = 0;

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT\n", __FUNCTION__ ));

    return 0;
}


void add_to_nap_ondemand_list(char* radioIfName, ULONG numAPs, wifi_neighbor_ap2_t* neighborapdata, char* freqband, ULONG channel)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER \n", __FUNCTION__ ));

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Radio Name[%s] Devices[%ld] \n", radioIfName, numAPs));
    struct neighboringapdata *ptr = malloc(sizeof(*ptr));
    if (ptr == NULL)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : Linked List Allocation Failed \n", __FUNCTION__ ));
        return;
    }
    else
    {
        ptr->radioName = strdup(radioIfName);
        ptr->numNeibouringAP = numAPs;
        ptr->napdata = neighborapdata;
        ptr->radioOperatingFrequencyBand = strdup(freqband); 
        ptr->radioChannel = channel;

        ptr->next = NULL;
        gettimeofday(&(ptr->timestamp), NULL);
#if !defined(UTC_ENABLE_ATOM) && !defined(_HUB4_PRODUCT_REQ_)	
        ptr->timestamp.tv_sec -= getTimeOffsetFromUtc();
#endif

        if (naphead == NULL)
        {
            naphead = napcurr = ptr;
        }
        else
        {
            napcurr->next = ptr;
            napcurr = ptr;
        }
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT\n", __FUNCTION__ ));

    return;
}

void print_nap_ondemand_list()
{
    int z = 0;
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER \n", __FUNCTION__ ));

    struct neighboringapdata  *ptr = naphead;
    while (ptr != NULL)
    {
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Head Ptr [%lx] TimeStamp[%d] for Node[%d] with radioName[%s] \n", (ulong)ptr, (int)ptr->timestamp.tv_sec, z, ptr->radioName));
        ptr = ptr->next;
        z++;
    }
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT\n", __FUNCTION__ ));
    return;
}

/* Function to delete the entire linked list */
void delete_nap_ondemand_list()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));

    napcurr = naphead;
    struct neighboringapdata* next = NULL;

    while (napcurr != NULL)
    {
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Deleting Node Head Ptr [%lx] with radioName[%s] \n", (ulong)napcurr, napcurr->radioName));
        next = napcurr->next;
        free(napcurr->radioName);
        free(napcurr->radioOperatingFrequencyBand);
        free(napcurr->napdata);
        free(napcurr);
        napcurr = next;
    }

    naphead = napcurr;

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT\n", __FUNCTION__ ));

    return;
}

int GetRadioNeighboringAPOnDemandData(int radioIndex, char* radioIfName)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));

    BOOL enabled = FALSE;
    wifi_neighbor_ap2_t *neighbor_ap_array=NULL;

    int ret = 0;
    UINT array_size = 0;
    ULONG channel = 0;
    char freqband[128] = {0};

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Radio Index is %d for InterfaceName [%s] \n", radioIndex, radioIfName));

    #ifdef RDK_ONEWIFI
         snprintf(tmp_buffer, sizeof(tmp_buffer), "Device.WiFi.Radio.%d.Enable", radioIndex+1);
         ret = rbus_getBoolValue(&enabled, tmp_buffer);
    #else
         ret = wifi_getRadioEnable(radioIndex, &enabled);
    #endif
    if (ret || enabled == FALSE)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : Radio %s is NOT ENABLED  or ERROR retured %d \n",__FUNCTION__ , radioIfName, ret));
        return ret;
    }
    #ifdef RDK_ONEWIFI
         snprintf(tmp_buffer, sizeof(tmp_buffer), "Device.WiFi.Radio.%d.Channel", radioIndex+1);
         ret = rbus_getUInt32Value(&channel, tmp_buffer);
    #else
         ret = wifi_getRadioChannel(radioIndex, &channel);
    #endif
    if (ret)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : radioIndex[%d] channel [%ld] \n", __FUNCTION__ , radioIndex, channel));
        return ret;
    }

    #ifdef RDK_ONEWIFI
         snprintf(tmp_buffer, sizeof(tmp_buffer), "Device.WiFi.Radio.%d.OperatingFrequencyBand", radioIndex+1);
         ret = rbus_getStringValue(freqband, tmp_buffer);
    #else
         ret = wifi_getRadioOperatingFrequencyBand(radioIndex, (char*)&freqband);
    #endif
    if (ret)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : radioIndex[%d] freqband [%s] \n",__FUNCTION__ , radioIndex, freqband));
        return ret;
    }

    #ifdef RDK_ONEWIFI
        if(!neighWiFiDiag_ondemand_executed)
            ret = rbus_wifi_getNeighboringWiFiDiagnosticResult2(&neighWiFiDiag_ondemand_executed, &neighbor_ap_array, &array_size);
        else
            CcspHarvesterTrace(("RDK_LOG_INFO, Harvester %s : rbus_getNeighboringWiFiDiagnosticResult2 already executed hence not running again\n", __FUNCTION__));
    #else
        ret = wifi_getNeighboringWiFiDiagnosticResult2(radioIndex, &neighbor_ap_array, &array_size);
    #endif
    if(( 0 == ret ) && ( NULL != neighbor_ap_array ) && ( array_size > 0 ) ) 
    {
        add_to_nap_ondemand_list(radioIfName, array_size, neighbor_ap_array, freqband, channel);
        int i;
        wifi_neighbor_ap2_t *ds = NULL;
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Neighboring AP Array Size is %d \n", array_size));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, ************Neighboring AP Data Begins************* \n"));

        for(i=0, ds=neighbor_ap_array; i<array_size; i++, ds++) 
        {
            /* CID :63833, 125383, 125383, 125383, 125383, 125383, 125383, 125383, 125383, 125383,
             * 125383, 71287, 125291, 61682, 68207, 125450, 124772, 53862, 65211, 125249,
             * 125513, 70030 - Printf arg type mismatch 
             */

            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AP[%d] ap_SSID [%s] \n",i, ds->ap_SSID));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AP[%d] ap_BSSID [%s] \n",i, ds->ap_BSSID));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AP[%d] ap_Mode [%s] \n",i, ds->ap_Mode));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AP[%d] ap_Channel %d \n", i, ds->ap_Channel));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AP[%d] ap_SignalStrength %d \n", i, ds->ap_SignalStrength));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AP[%d] ap_SecurityModeEnabled [%s] \n",i, ds->ap_SecurityModeEnabled));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AP[%d] ap_EncryptionMode [%s] \n",i, ds->ap_EncryptionMode));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AP[%d] ap_OperatingFrequencyBand [%s] \n",i, ds->ap_OperatingFrequencyBand));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AP[%d] ap_SupportedStandards [%s] \n",i, ds->ap_SupportedStandards));        
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AP[%d] ap_OperatingStandards [%s] \n",i, ds->ap_OperatingStandards));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AP[%d] ap_OperatingChannelBandwidth [%s] \n",i, ds->ap_OperatingChannelBandwidth));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AP[%d] ap_BeaconPeriod %d \n", i, ds->ap_BeaconPeriod));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AP[%d] ap_Noise %d \n", i, ds->ap_Noise));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AP[%d] ap_BasicDataTransferRates [%s] \n",i, ds->ap_BasicDataTransferRates)); 
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AP[%d] ap_SupportedDataTransferRates [%s] \n",i, ds->ap_SupportedDataTransferRates));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AP[%d] ap_DTIMPeriod %d \n", i, ds->ap_DTIMPeriod));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AP[%d] ap_ChannelUtilization %d \n", i, ds->ap_ChannelUtilization));

        }

        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, ************Neighboring AP Data Ends************* \n"));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, ***************************************** \n"));

        print_nap_ondemand_list();

    } // end of if statement
    else
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : wifi_getNeighboringWiFiDiagnosticResult2 Return[%d] array_size [%d] \n", __FUNCTION__ , ret, array_size));
    } 

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT \n", __FUNCTION__ ));
    return ret;
}

void* StartNeighboringAPOnDemandHarvesting(void* arg)
{
    int ret = 0;
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER \n", __FUNCTION__ ));

    CcspHarvesterEventTrace(("RDK_LOG_DEBUG, Harvester %s : Starting Thread to start NeighboringAP OnDemand Harvesting  \n", __FUNCTION__ ));

    while (!ret && GetNAPOnDemandHarvestingStatus()) {

        ULONG output = 0;
        int k = 0;
        char radioIfName[128] = {0};
        #ifdef RDK_ONEWIFI
             ret = rbus_getUInt32Value(&output, "Device.WiFi.RadioNumberOfEntries");
        #else
             int ret =  wifi_getRadioNumberOfEntries(&output); //Tr181
        #endif
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Number of Radio Entries = %ld ReturnValue [%d]\n", output, ret));
        if (!ret && output > 0)
        {
            for (k = 0; k < output; k++)
            {            
                #ifdef RDK_ONEWIFI
                    snprintf(tmp_buffer, sizeof(tmp_buffer), "Device.WiFi.Radio.%d.Name", k+1);
                    ret = rbus_getStringValue(radioIfName, tmp_buffer);
                #else
                    ret = wifi_getRadioIfName(k, (char*)&radioIfName);
                #endif
                if (ret)
                {
                    CcspHarvesterTrace(("RDK_LOG_WARN, wifi_getRadioIfName returned error [%d] \n", ret));
                }

                ret = GetRadioNeighboringAPOnDemandData(k, (char*)&radioIfName);
                if (ret)
                {
                    CcspHarvesterTrace(("RDK_LOG_WARN, GetRadioNeighboringAPData returned error [%d] for radioIfName[%s] \n", ret, radioIfName));
                }
            }

            struct neighboringapdata* ptr = naphead;
            if(ptr)
            {
                CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Before Sending NeighboringAPOnDemand Scan Data to WebPA and AVRO \n"));
                harvester_report_neighboringap(ptr);
                delete_nap_ondemand_list();
            }

            SetNAPOnDemandHarvestingStatus(FALSE);
            #ifdef RDK_ONEWIFI
                neighWiFiDiag_ondemand_executed = false;
            #endif
        }
        else
        {
            CcspHarvesterTrace(("RDK_LOG_WARN, wifi_getRadioNumberOfEntries Error [%d] or No SSID [%ld] \n", ret, output));
        }

    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT \n", __FUNCTION__ ));
    CcspHarvesterEventTrace(("RDK_LOG_DEBUG, Harvester %s : Thread Stopped for NeighboringAP OnDemand Harvesting  \n", __FUNCTION__ ));

    return NULL;
}

// End of File

