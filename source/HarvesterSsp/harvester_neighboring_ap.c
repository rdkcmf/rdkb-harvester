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
#include <semaphore.h>
#include "harvester_neighboring_ap.h"
#include "harvester_avro.h"
#include "ccsp_harvesterLog_wrapper.h"
#include "safec_lib_common.h"
#ifdef RDK_ONEWIFI
#include "harvester_rbus_api.h"

static bool neighWiFiDiag_executed = false;
#endif

static pthread_mutex_t napMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t napCond = PTHREAD_COND_INITIALIZER;

ULONG NAPReportingPeriodDefault = 43200;
ULONG NAPPollingPeriodDefault = 21600;

ULONG NAPReportingPeriod = 43200;
ULONG NAPPollingPeriod = 21600;

ULONG currentNAPReportingPeriod = 0;

BOOL NAPHarvesterStatus = FALSE;
ULONG NAPOverrideTTL = 43200;
ULONG NAPOverrideTTLDefault = 43200;


ULONG NeighboringAPPeriods[8] = {300,900,1800,3600,10800,21600,43200,86400};

BOOL isvalueinNAParray(ULONG val, ULONG *arr, int size);

#ifdef RDK_ONEWIFI
char ap_buffer[128] = {'\0'};
#endif

#if !defined(UTC_ENABLE_ATOM) && !defined(_HUB4_PRODUCT_REQ_)
extern int getTimeOffsetFromUtc();
#endif

static struct neighboringapdata *headnode = NULL;
static struct neighboringapdata *currnode = NULL;

void* StartNeighboringAPHarvesting( void *arg );
int _napsyscmd(char *cmd, char *retBuf, int retBufSize);
int setNAPCurrentTimeFromDmCli();
void add_to_nap_list(char* radioIfName, ULONG numAPs, wifi_neighbor_ap2_t* neighborapdata, char* freqband, ULONG channel);
void print_nap_list();
void delete_nap_list();
int GetRadioNeighboringAPData(int radioIndex, char* radioIfName);
extern void ap_avro_cleanup();
extern ulong GetCurrentTimeInSecond();

// RDKB-9258 : set polling and reporting periods to NVRAM after TTL expiry
extern ANSC_STATUS SetNAPPollingPeriodInNVRAM(ULONG pPollingVal);
extern ANSC_STATUS SetNAPReportingPeriodInNVRAM(ULONG pReportingVal);

static void WaitForPthreadConditionTimeoutNAP()
{
    struct timespec _ts = { 0 };
    struct timespec _now = { 0 };
    int n;

    pthread_mutex_lock(&napMutex);

    clock_gettime(CLOCK_REALTIME, &_now);
    _ts.tv_sec = _now.tv_sec + GetNAPPollingPeriod();

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : Waiting for %lu sec\n",__FUNCTION__,GetNAPPollingPeriod()));

    n = pthread_cond_timedwait(&napCond, &napMutex, &_ts);
    if(n == ETIMEDOUT)
    {
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : pthread_cond_timedwait TIMED OUT!!!\n",__FUNCTION__));
    }
    else if (n == 0)
    {
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : pthread_cond_timedwait SIGNALLED OK!!!\n",__FUNCTION__));
    }
    else
    {
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, LMLite %s : pthread_cond_timedwait ERROR!!!\n",__FUNCTION__));
    }

    pthread_mutex_unlock(&napMutex);

}

int SetNAPHarvestingStatus(BOOL status)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s  Old[%d] New[%d] \n", __FUNCTION__, NAPHarvesterStatus, status ));
    if (NAPHarvesterStatus != status)
        NAPHarvesterStatus = status;
    else
        return 0;

    if (NAPHarvesterStatus)
    {
        pthread_t tid;

        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : Starting Thread to start NeighboringAP Harvesting  \n", __FUNCTION__ ));

        if (pthread_create(&tid, NULL, StartNeighboringAPHarvesting, NULL))
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : Failed to Start Thread to start NeighboringAP Harvesting  \n", __FUNCTION__ ));
            return ANSC_STATUS_FAILURE;
        }
    }
    else
    {
        int ret;
        pthread_mutex_lock(&napMutex);
        ret = pthread_cond_signal(&napCond);
        pthread_mutex_unlock(&napMutex);
        if (ret == 0)
        {
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : pthread_cond_signal success\n", __FUNCTION__ ));
        }
        else
        {
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : pthread_cond_signal fail\n", __FUNCTION__ ));
        }
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

    return 0;
}

BOOL isvalueinNAParray(ULONG val, ULONG *arr, int size)
{
    int i;
    for (i=0; i < size; i++) {
        if (arr[i] == val)
            return true;
    }
    return false;
}

BOOL GetNAPHarvestingStatus()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT NAPHarvesterStatus[%d] \n", __FUNCTION__, NAPHarvesterStatus ));
    return NAPHarvesterStatus;
}

int SetNAPReportingPeriod(ULONG interval)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT Old[%lu] New[%lu] \n", __FUNCTION__, NAPReportingPeriod, interval ));
    NAPReportingPeriod = interval;
    SetNAPOverrideTTL(2*NAPReportingPeriod);
    return 0;
}

ULONG GetNAPReportingPeriod()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT NAPReportingPeriod[%lu] \n", __FUNCTION__, NAPReportingPeriod ));
    return NAPReportingPeriod;
}

int SetNAPPollingPeriod(ULONG interval)
{
    int ret;
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT Old[%lu] New[%lu] \n", __FUNCTION__, NAPPollingPeriod, interval ));
    NAPPollingPeriod = interval;

    pthread_mutex_lock(&napMutex);
    currentNAPReportingPeriod = GetNAPReportingPeriod();

    ret = pthread_cond_signal(&napCond);
    pthread_mutex_unlock(&napMutex);
    if (ret == 0)
    {
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : pthread_cond_signal success\n",__FUNCTION__));
    }
    else
    {
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : pthread_cond_signal fail\n",__FUNCTION__));
    }

    return 0;
}

ULONG GetNAPPollingPeriod()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT NAPPollingPeriod[%lu] \n", __FUNCTION__, NAPPollingPeriod ));
    return NAPPollingPeriod;
}

int SetNAPReportingPeriodDefault(ULONG interval)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT Old[%lu] New[%lu] \n", __FUNCTION__, NAPReportingPeriodDefault, interval ));
    NAPReportingPeriodDefault = interval;
    return 0;
}

ULONG GetNAPReportingPeriodDefault()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT NAPReportingPeriodDefault[%lu] \n", __FUNCTION__, NAPReportingPeriodDefault ));
    return NAPReportingPeriodDefault;
}

int SetNAPPollingPeriodDefault(ULONG interval)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT Old[%lu] New[%lu] \n", __FUNCTION__, NAPPollingPeriodDefault, interval ));
    NAPPollingPeriodDefault = interval;
    return 0;
}

ULONG GetNAPPollingPeriodDefault()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT NAPPollingPeriodDefault[%lu] \n", __FUNCTION__, NAPPollingPeriodDefault ));
    return NAPPollingPeriodDefault;
}

ULONG GetNAPOverrideTTL()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT NAPOverrideTTL[%lu] \n", __FUNCTION__, NAPOverrideTTL ));
    return NAPOverrideTTL;
}

int SetNAPOverrideTTL(ULONG count)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT Old[%lu] New[%lu] \n", __FUNCTION__, NAPOverrideTTL, count ));
    NAPOverrideTTL = count;
    return 0;
}

ULONG GetNAPOverrideTTLDefault()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT NAPOverrideTTLDefault[%lu] \n", __FUNCTION__, NAPOverrideTTLDefault ));
    return NAPOverrideTTLDefault;
}

BOOL ValidateNAPPeriod(ULONG interval)
{
    return isvalueinNAParray(interval, NeighboringAPPeriods, 8);
} 

int _napsyscmd(char *cmd, char *retBuf, int retBufSize)
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


void add_to_nap_list(char* radioIfName, ULONG numAPs, wifi_neighbor_ap2_t* neighborapdata, char* freqband, ULONG channel)
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

        if (headnode == NULL)
        {
            headnode = currnode = ptr;
        }
        else
        {
            currnode->next = ptr;
            currnode = ptr;
        }
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT\n", __FUNCTION__ ));

    return;
}

void print_nap_list()
{
    int z = 0;
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER \n", __FUNCTION__ ));

    struct neighboringapdata  *ptr = headnode;
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
void delete_nap_list()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));

    currnode = headnode;
    struct neighboringapdata* next = NULL;

    while (currnode != NULL)
    {
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Deleting Node Head Ptr [%lx] with radioName[%s] \n", (ulong)currnode, currnode->radioName));
        next = currnode->next;
        free(currnode->radioName);
        free(currnode->radioOperatingFrequencyBand);
        free(currnode->napdata);
        free(currnode);
        currnode = next;
    }

    headnode = currnode;

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT\n", __FUNCTION__ ));

    return;
}

int GetRadioNeighboringAPData(int radioIndex, char* radioIfName)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    int ret = 0;
    BOOL enabled = FALSE;
    wifi_neighbor_ap2_t *neighbor_ap_array=NULL;

    UINT array_size = 0;
    ULONG channel = 0;
    char freqband[128] = {0};

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Radio Index is %d for InterfaceName [%s] \n", radioIndex, radioIfName));
    #ifdef RDK_ONEWIFI
         snprintf(ap_buffer, sizeof(ap_buffer), "Device.WiFi.Radio.%d.Enable", radioIndex+1);
         ret = rbus_getBoolValue(&enabled, ap_buffer);
    #else
         ret = wifi_getRadioEnable(radioIndex, &enabled);
    #endif
    if (ret || enabled == FALSE)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : Radio %s is NOT ENABLED  or ERROR retured %d \n",__FUNCTION__ , radioIfName, ret));
        return ret;
    }
    #ifdef RDK_ONEWIFI
         snprintf(ap_buffer, sizeof(ap_buffer), "Device.WiFi.Radio.%d.Channel", radioIndex+1);
         ret = rbus_getUInt32Value(&channel, ap_buffer);
    #else
         ret = wifi_getRadioChannel(radioIndex, &channel);
    #endif
    if (ret)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : radioIndex[%d] channel [%ld] \n", __FUNCTION__ , radioIndex, channel));
        return ret;
    }
    #ifdef RDK_ONEWIFI
         snprintf(ap_buffer, sizeof(ap_buffer), "Device.WiFi.Radio.%d.OperatingFrequencyBand", radioIndex+1);
         ret = rbus_getStringValue(freqband, ap_buffer);
    #else
         ret = wifi_getRadioOperatingFrequencyBand(radioIndex, (char*)&freqband);
    #endif
    if (ret)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : radioIndex[%d] freqband [%s] \n",__FUNCTION__ , radioIndex, freqband));
        return ret;
    }
    #ifdef RDK_ONEWIFI
        if(!neighWiFiDiag_executed)
            ret = rbus_wifi_getNeighboringWiFiDiagnosticResult2(&neighWiFiDiag_executed, &neighbor_ap_array, &array_size);
        else
            CcspHarvesterTrace(("RDK_LOG_INFO, Harvester %s : rbus_getNeighboringWiFiDiagnosticResult2 already executed hence not running again\n", __FUNCTION__));
    #else     
        ret = wifi_getNeighboringWiFiDiagnosticResult2(radioIndex, &neighbor_ap_array, &array_size);
    #endif
    if(( 0 == ret ) && ( NULL != neighbor_ap_array ) && ( array_size > 0 ) ) 
    {
        add_to_nap_list(radioIfName, array_size, neighbor_ap_array, freqband, channel);

        int i;
        wifi_neighbor_ap2_t *ds = NULL;
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, ************Neighboring AP Data Begins************* \n"));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Neighboring AP Array Size is %d \n", array_size));
        for(i=0, ds=neighbor_ap_array; i<array_size; i++, ds++) 
        {
            /* CID: 58722, 125343, 65523, 125446, 67087,125542, 124840, 64381, 68840,
             * 125504, 61914, 124981, 124988, 70460, 125298, 62428, 125396, 56663:  
             * Invalid type in argument to printf format specifier & Printf arg type mismatch
             */

            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AP[%d] ap_SSID [%s] \n",i, ds->ap_SSID));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AP[%d] ap_BSSID [%s] \n",i, ds->ap_BSSID));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AP[%d] ap_Mode [%s] \n",i,  ds->ap_Mode));
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

        print_nap_list();

    } // end of if statement
    else
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : wifi_getNeighboringWiFiDiagnosticResult2 Return[%d] array_size [%d] \n", __FUNCTION__, ret, array_size));
    } 

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT \n", __FUNCTION__ ));
    return ret;
}

void* StartNeighboringAPHarvesting( void *arg )
{
    int ret = 0;
    ULONG uDefaultVal = 0;
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER \n", __FUNCTION__ ));
    CcspHarvesterEventTrace(("RDK_LOG_DEBUG, Harvester %s : Starting Thread to start NeighboringAP Harvesting  \n", __FUNCTION__ ));

    currentNAPReportingPeriod = GetNAPReportingPeriod();

    if(GetNAPOverrideTTL() < currentNAPReportingPeriod)
    {
        SetNAPOverrideTTL(currentNAPReportingPeriod);
    }

    while (!ret && GetNAPHarvestingStatus()) {

        ULONG output = 0;
        int k = 0;
        int ret = 0;
        char radioIfName[128] = {0};
        #ifdef RDK_ONEWIFI
             ret = rbus_getUInt32Value(&output, "Device.WiFi.RadioNumberOfEntries");
        #else
             ret =  wifi_getRadioNumberOfEntries(&output); //Tr181
        #endif
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Number of Radio Entries = %ld ReturnValue [%d]\n", output, ret));
        if (!ret && output > 0)
        {
            for (k = 0; k < output; k++)
            {
                #ifdef RDK_ONEWIFI
                    snprintf(ap_buffer, sizeof(ap_buffer), "Device.WiFi.Radio.%d.Name", k+1);
                    ret = rbus_getStringValue(radioIfName, ap_buffer);
                #else
                    ret = wifi_getRadioIfName(k, (char*)&radioIfName);
                #endif
                if (ret)
                {
                    CcspHarvesterTrace(("RDK_LOG_ERROR, wifi_getRadioIfName returned error [%d] \n", ret));
                }

                ret = GetRadioNeighboringAPData(k, (char*)&radioIfName);
                if (ret)
                {
                    CcspHarvesterTrace(("RDK_LOG_ERROR, GetRadioNeighboringAPData returned error [%d] for radioIfName[%s] \n", ret, radioIfName));
                }
            }

            currentNAPReportingPeriod = currentNAPReportingPeriod + GetNAPPollingPeriod();
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, currentNAPReportingPeriod[%ld]\n", currentNAPReportingPeriod));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, GetNAPReportingPeriod()[%ld]\n", GetNAPReportingPeriod()));

            if (currentNAPReportingPeriod >= GetNAPReportingPeriod())
            {
                struct neighboringapdata* ptr = headnode;
                if(ptr)
                {
                    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Before Sending to WebPA and AVRO NAPReportingPeriod[%ld]  \n", GetNAPReportingPeriod()));
                    harvester_report_neighboringap(ptr);
                    delete_nap_list();
                    #ifdef RDK_ONEWIFI
                        neighWiFiDiag_executed = false;
                    #endif
                }

                currentNAPReportingPeriod = 0;
            }

            if(GetNAPOverrideTTL())
            {
                SetNAPOverrideTTL(GetNAPOverrideTTL() - GetNAPPollingPeriod());
            }

            if(!GetNAPOverrideTTL())
            {
                //Polling
                uDefaultVal = GetNAPPollingPeriodDefault();
                SetNAPPollingPeriod( uDefaultVal );
                //RDKB-9258 : Saving polling period to NVRAM.
                SetNAPPollingPeriodInNVRAM( uDefaultVal );

                //Reporting
                uDefaultVal = GetNAPReportingPeriodDefault();
                SetNAPReportingPeriod( uDefaultVal );
                //RDKB-9258 : Saving reporting period to NVRAM.
                SetNAPReportingPeriodInNVRAM( uDefaultVal );

                //TTL
                SetNAPOverrideTTL(GetNAPOverrideTTLDefault());
            }

            WaitForPthreadConditionTimeoutNAP();

        }
        else
        {
            CcspHarvesterTrace(("RDK_LOG_DEBUG, wifi_getRadioNumberOfEntries Error [%d] or No SSID [%ld] \n", ret, output));
        }

        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, GetNAPPollingPeriod[%ld]\n", GetNAPPollingPeriod()));
    }
    ap_avro_cleanup();
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT \n", __FUNCTION__ ));
    CcspHarvesterEventTrace(("RDK_LOG_DEBUG, Harvester %s : Thread Stopped for NeighboringAP Harvesting  \n", __FUNCTION__ ));

    return NULL;
}

// End of File

