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
#include <stdbool.h>
#include <semaphore.h>
#include "harvester_associated_devices.h"
#include "harvester_avro.h"
#include "ccsp_harvesterLog_wrapper.h"
#include "report_common.h"
#include "safec_lib_common.h"


#define PUBLIC  0
#define PRIVATE 1

#define PUBLIC_WIFI_IDX_STARTS  4
#define PUBLIC_WIFI_IDX_ENDS  5
#define PRIVATE_WIFI_IDX_STARTS  0
#define PRIVATE_WIFI_IDX_ENDS  1

/* MAX SSID name buffer set as 512 bytes for qtn component*/
#define STR_BUF_MAX 512

static pthread_mutex_t idwMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t idwCond = PTHREAD_COND_INITIALIZER;

static sem_t mutex;

ULONG AssociatedDevicePeriods[] = {1,5,10,15,30,60,300,900,1800,3600,10800,21600,43200,86400};

ULONG IDWPollingPeriodDefault = DEFAULT_POLLING_INTERVAL;
ULONG IDWReportingPeriodDefault = DEFAULT_REPORTING_INTERVAL;

ULONG IDWPollingPeriod = DEFAULT_POLLING_INTERVAL;
ULONG IDWReportingPeriod = DEFAULT_REPORTING_INTERVAL;

ULONG currentReportingPeriod = 0;
BOOL IDWHarvesterStatus = FALSE;

ULONG IDWOverrideTTL = TTL_INTERVAL;
ULONG IDWOverrideTTLDefault = DEFAULT_TTL_INTERVAL;

bool isvalueinarray(ULONG val, ULONG *arr, int size);

void* StartAssociatedDeviceHarvesting( void *arg );
int _syscmd(char *cmd, char *retBuf, int retBufSize);
void add_to_list(struct associateddevicedata **headnode, char* ssid, ULONG devices, wifi_associated_dev_t* devicedata, char* freqband, ULONG channel, char* intfcmacid);
void print_list( struct associateddevicedata *head );
void delete_list( struct associateddevicedata *head );
int GetWiFiApGetAssocDevicesData(int ServiceType, int wlanIndex, char* pSsid);

static struct associateddevicedata *headnodeprivate = NULL;
static struct associateddevicedata *headnodepublic = NULL;

// RDKB-9258 : set polling and reporting periods to NVRAM after TTL expiry
extern ANSC_STATUS SetIDWPollingPeriodInNVRAM(ULONG pPollingVal);
extern ANSC_STATUS SetIDWReportingPeriodInNVRAM(ULONG pReportingVal);
extern void harvester_avro_cleanup();
char* GetCurrentTimeString()
{
    time_t current_time;
    char* c_time_string;

    /* Obtain current time. */
    current_time = time(NULL);

    /* Convert to local time format. */
    c_time_string = ctime(&current_time);

    return c_time_string;
}


ulong GetCurrentTimeInSecond()
{
    struct timespec ts;
    // get current time in second
    clock_gettime(CLOCK_REALTIME, &ts);
    return (ulong)ts.tv_sec;
}

static void WaitForPthreadConditionTimeoutIDW()
{
    struct timespec _ts = { 0 };
    struct timespec _now = { 0 };
    int n;

    pthread_mutex_lock(&idwMutex);

    clock_gettime(CLOCK_REALTIME, &_now);
    _ts.tv_sec = _now.tv_sec + GetIDWPollingPeriod();

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : Waiting for %d sec\n",__FUNCTION__,GetIDWPollingPeriod()));

    n = pthread_cond_timedwait(&idwCond, &idwMutex, &_ts);
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

    pthread_mutex_unlock(&idwMutex);

}

bool isvalueinarray(ULONG val, ULONG *arr, int size)
{
    int i;
    for (i=0; i < size; i++) {
        if (arr[i] == val)
            return true;
    }
    return false;
}


int SetIDWHarvestingStatus(BOOL status)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : Old[%d] New[%d] \n", __FUNCTION__, IDWHarvesterStatus, status ));

    if (IDWHarvesterStatus != status)
        IDWHarvesterStatus = status;
    else
        return 0;

    if (IDWHarvesterStatus)
    {
        pthread_t tid;

        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : Starting Thread to start DeviceData Harvesting  \n", __FUNCTION__ ));

        if (pthread_create(&tid, NULL, StartAssociatedDeviceHarvesting, NULL))
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : Failed to Start Thread to start DeviceData Harvesting  \n", __FUNCTION__ ));
            return ANSC_STATUS_FAILURE;
        }
	CcspHarvesterTrace(("RDK_LOG_WARN, Harvester InterfaceDeviceWifi Report STARTED %s \n",__FUNCTION__));
    }
    else
    {
        int ret;
        pthread_mutex_lock(&idwMutex);
        ret = pthread_cond_signal(&idwCond);
        pthread_mutex_unlock(&idwMutex);
        if (ret == 0)
        {
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : pthread_cond_signal success\n", __FUNCTION__ ));
        }
        else
        {
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : pthread_cond_signal fail\n", __FUNCTION__ ));
        }
	CcspHarvesterTrace(("RDK_LOG_WARN, Harvester InterfaceDeviceWifi Report STOPPED %s \n",__FUNCTION__));
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

    return 0;
}

BOOL GetIDWHarvestingStatus()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT RET[%d] \n", __FUNCTION__, IDWHarvesterStatus ));
    return IDWHarvesterStatus;
}

int SetIDWReportingPeriod(ULONG interval)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT Old[%ld] New[%ld] \n", __FUNCTION__, IDWReportingPeriod, interval ));
    IDWReportingPeriod = interval;
    return 0;
}

ULONG GetIDWReportingPeriod()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT RET[%ld] \n", __FUNCTION__, IDWReportingPeriod ));
    return IDWReportingPeriod;
}

int SetIDWPollingPeriod(ULONG interval)
{
    int ret;
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s Old[%ld] New[%ld] \n", __FUNCTION__, IDWPollingPeriod, interval ));
    IDWPollingPeriod = interval;

    pthread_mutex_lock(&idwMutex);
    currentReportingPeriod = GetIDWReportingPeriod();

    ret = pthread_cond_signal(&idwCond);
    pthread_mutex_unlock(&idwMutex);
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

BOOL ValidateIDWPeriod(ULONG interval)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    BOOL ret = FALSE;
    ret = isvalueinarray(interval, AssociatedDevicePeriods, sizeof(AssociatedDevicePeriods)/sizeof(AssociatedDevicePeriods[ 0 ]));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT RET[%d] \n", __FUNCTION__ , ret ));
    return ret;
} 

ULONG GetIDWPollingPeriod()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT RET[%ld] \n", __FUNCTION__, IDWPollingPeriod ));
    return IDWPollingPeriod;
}

int SetIDWReportingPeriodDefault(ULONG interval)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT Old[%ld] New[%ld] \n", __FUNCTION__, IDWReportingPeriodDefault, interval ));
    IDWReportingPeriodDefault = interval;
    return 0;
}

ULONG GetIDWReportingPeriodDefault()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT RET[%ld] \n", __FUNCTION__, IDWReportingPeriodDefault ));
    return IDWReportingPeriodDefault;
}

int SetIDWPollingPeriodDefault(ULONG interval)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT Old[%ld] New[%ld] \n", __FUNCTION__, IDWPollingPeriodDefault, interval ));
    IDWPollingPeriodDefault = interval;
    return 0;
}

ULONG GetIDWPollingPeriodDefault()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT RET[%ld] \n", __FUNCTION__, IDWPollingPeriodDefault ));
    return IDWPollingPeriodDefault;
}

ULONG GetIDWOverrideTTL()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT RET[%ld] \n", __FUNCTION__, IDWOverrideTTL ));
    return IDWOverrideTTL;
}

int SetIDWOverrideTTL(ULONG count)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT Old[%ld] New[%ld] \n", __FUNCTION__, IDWOverrideTTL, count ));
    IDWOverrideTTL = count;
    return 0;
}

ULONG GetIDWOverrideTTLDefault()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT RET[%ld] \n", __FUNCTION__, IDWOverrideTTLDefault ));
    return IDWOverrideTTLDefault;
}

int _syscmd(char *cmd, char *retBuf, int retBufSize)
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

        fgets(ptr, bufbytes, f);
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

#if !defined(UTC_ENABLE_ATOM) && !defined(_HUB4_PRODUCT_REQ_)
int getTimeOffsetFromUtc()
{
    static int tm_offset = 0;
    static bool offset_available = false;
    errno_t                         rc       = -1;

    if(offset_available)
    {
        return tm_offset;
    }
    else
    {
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
        char timezonecmd[128] = {0};
        char timezonearr[32] = {0};
        int ret  = 0;

        rc = sprintf_s(timezonecmd,sizeof(timezonecmd), "dmcli eRT getv Device.Time.TimeOffset | grep value | awk '{print $5}'");
        if(rc < EOK)
        {
          ERR_CHK(rc);
          return -1;
        }
        ret = _syscmd(timezonecmd, timezonearr, sizeof(timezonearr));
        if(ret)
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : Executing Syscmd for DMCLI TimeOffset [%d] \n",__FUNCTION__, ret));
            return ret;
        }

        if (sscanf(timezonearr, "%d", &tm_offset) != 1)
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : Parsing Error for TimeOffset \n", __FUNCTION__ ));
            return -1;
        }

        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s TimeOffset[%d] EXIT \n", __FUNCTION__, tm_offset ));
        offset_available = true;
        return tm_offset;
    }

}
#endif


void add_to_list(struct associateddevicedata **headnode, char* ssid, ULONG devices, wifi_associated_dev_t* devicedata, char* freqband, ULONG channel, char* intfcmacid)
{
    errno_t rc = -1;
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, SSID Input[%s] Devices[%ld] \n", ssid, devices));
    struct associateddevicedata *ptr = malloc(sizeof(struct associateddevicedata));
    if (ptr == NULL)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s :  Linked List Allocation Failed \n", __FUNCTION__ ));
        return;
    }
    else
    {
        /* Coverity Fix CID: 60030 NULL_RETURNS */
        rc = memset_s(ptr, sizeof(struct associateddevicedata), 0, sizeof(struct associateddevicedata));
        ERR_CHK(rc);
        ptr->sSidName = strdup(ssid);
        ptr->bssid = strdup(intfcmacid);
        ptr->numAssocDevices = devices;
        ptr->devicedata = devicedata;
        ptr->radioOperatingFrequencyBand = strdup(freqband); //Possible value 2.4Ghz and 5.0 Ghz
        ptr->radioChannel = channel;
        ptr->next = NULL;
        gettimeofday(&(ptr->timestamp), NULL);
#if !defined(UTC_ENABLE_ATOM) && !defined(_HUB4_PRODUCT_REQ_)
        ptr->timestamp.tv_sec -= getTimeOffsetFromUtc();
#endif
        if (*headnode == NULL)
        {
            *headnode = ptr; //Important - headnode only assigned when it is a NEW list
        }
        else
        {
            struct associateddevicedata *prevnode, *currnode;

            // transverse to end of list and append new list
            prevnode = *headnode;
            currnode = (*headnode)->next;
            while ( currnode != NULL)
            {
                prevnode = currnode;
                currnode = currnode->next;
            };
            prevnode->next = ptr; // add to list
        }
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT\n", __FUNCTION__ ));

    return;
}

void print_list( struct associateddevicedata *headnode)
{
    int z = 0;
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    struct associateddevicedata  *ptr = headnode;
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Head Ptr [%lx]\n", (ulong)headnode));
    while (ptr != NULL)
    {
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : Head Ptr [%lx] TimeStamp[%d] for Node[%d] with SSID[%s] \n", __FUNCTION__ ,(ulong)ptr, (int)ptr->timestamp.tv_sec, z, ptr->sSidName));
        ptr = ptr->next;
        z++;
    }
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT \n", __FUNCTION__ ));
    return;
}

/* Function to delete the entire linked list */
void delete_list(  struct associateddevicedata *headnode )
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));

    struct associateddevicedata *currnode = headnode;
    struct associateddevicedata* next = NULL;

    while (currnode != NULL)
    {
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : Deleting IDW Node Head Ptr [%lx] with SSID[%s] \n",__FUNCTION__, (ulong)currnode, currnode->sSidName));
        next = currnode->next;
        free(currnode->sSidName);
        free(currnode->bssid);
        free(currnode->radioOperatingFrequencyBand);
        free(currnode->devicedata);
        free(currnode);
        currnode = next;
    }
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT \n", __FUNCTION__ ));

    return;
}

int GetWiFiApGetAssocDevicesData(int ServiceType, int wlanIndex, char* pSsid)
{

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));

    BOOL enabled = FALSE;
    wifi_associated_dev_t *wifi_associated_dev_array = NULL;
    UINT array_size = 0;
    int radioIndex = 0;
    char interfaceMAC[128] = {0};
    ULONG channel = 0;
    char freqband[128] = {0};

    int ret = wifi_getApEnable(wlanIndex, &enabled);
    if (ret || enabled == FALSE)
    {
	if ( ServiceType == PUBLIC )
	{
		/* Disabling this log as Public wifi SSIDs are disabled by default */
		CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : SSID %s is NOT ENABLED  or ERROR retured %d \n",__FUNCTION__, pSsid, ret));
	}
	else
	{
		CcspHarvesterTrace(("RDK_LOG_INFO, Harvester %s : SSID %s is NOT ENABLED  or ERROR retured %d \n",__FUNCTION__, pSsid, ret));
	}
        return ret;
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : WLAN Index is %d for SSID %s \n", __FUNCTION__, wlanIndex, pSsid));

    ret = wifi_getBaseBSSID(wlanIndex, (char*)&interfaceMAC); //Tr181
    if (ret)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : wlanIndex[%d] BSSID [%s] \n",__FUNCTION__, wlanIndex, interfaceMAC));
        return ret;
    }

    ret = wifi_getSSIDRadioIndex(wlanIndex, &radioIndex);
    if (ret)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : wlanIndex[%d] radioIndex [%d] \n",__FUNCTION__, wlanIndex, radioIndex));
        return ret;
    }

    ret = wifi_getRadioChannel(radioIndex, &channel);
    if (ret)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : wlanIndex[%d] channel [%ld] \n",__FUNCTION__, wlanIndex, channel));
        return ret;
    }


    ret = wifi_getRadioOperatingFrequencyBand(radioIndex, (char*)&freqband);
    if (ret)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : radioIndex[%d] freqband [%s] \n",__FUNCTION__, radioIndex, freqband));
        return ret;
    }


    //hal would allocate the array
    ret = wifi_getApAssociatedDeviceDiagnosticResult(wlanIndex, &wifi_associated_dev_array, &array_size);
    if (!ret && wifi_associated_dev_array && array_size > 0)
    {
        struct associateddevicedata **headnode = NULL;
        if ( ServiceType == PUBLIC )
        {
            headnode = (struct associateddevicedata **)headnodepublic;
            add_to_list((struct associateddevicedata **)&headnode,  pSsid, array_size, wifi_associated_dev_array, (char*)&freqband, channel, (char*)&interfaceMAC);
            headnodepublic = (struct associateddevicedata *)headnode; //Important - headnode only change when it is a NEW list
        }
        else
        {
            headnode = (struct associateddevicedata **)headnodeprivate;
            add_to_list((struct associateddevicedata **)&headnode, pSsid, array_size, wifi_associated_dev_array, (char*)&freqband, channel, (char*)&interfaceMAC);
            headnodeprivate = (struct associateddevicedata *)headnode; //Important - headnode only change when it is a NEW list
        }

        int i, j;
        wifi_associated_dev_t *ps = NULL;
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, ************Device Data Begins************* \n"));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Device Array Size is %d \n", array_size));
        for (i = 0, ps = wifi_associated_dev_array; i < array_size; i++, ps++)
        {
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Device[%d] DeviceMacAddress [", i));
            if(consoleDebugEnable)
            {
             for (j = 0; j < 6; j++)
                fprintf(stderr, "%02x", ps->cli_MACAddress[j]);
            fprintf(stderr, "]\n");               
            }


            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Device[%d] Device-IPAddress [%s] \n", i, (char*)&(ps->cli_IPAddress)));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Device[%d] OperatingStandard [%s] \n", i, (char*)&(ps->cli_OperatingStandard)));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Device[%d] OperatingChannelBandwidth [%s] \n", i, (char*)&(ps->cli_OperatingChannelBandwidth)));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Device[%d] AuthenticationState %d \n", i, ps->cli_AuthenticationState));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Device[%d] LastDataDownlinkRate %d \n", i, ps->cli_LastDataDownlinkRate));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Device[%d] LastDataUplinkRate %d \n", i, ps->cli_LastDataUplinkRate));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Device[%d] SignalStrength %d \n", i, ps->cli_SignalStrength));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Device[%d] BytesReceived %lu \n", i, ps->cli_BytesReceived));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Device[%d] BytesSent %lu \n", i, ps->cli_BytesSent));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Device[%d] RSSI %d \n", i, ps->cli_RSSI));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Device[%d] Active %d \n", i, ps->cli_Active));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Device[%d] Retransmissions %d \n", i, ps->cli_Retransmissions));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Device[%d] SNR %d \n", i, ps->cli_SNR));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Device[%d] DataFramesSentAck %lu \n", i, ps->cli_DataFramesSentAck));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Device[%d] DataFramesSentNoAck %lu \n", i, ps->cli_DataFramesSentNoAck));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Device[%d] MinRSSI %d \n", i, ps->cli_MinRSSI));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Device[%d] MaxRSSI %d \n", i, ps->cli_MaxRSSI));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Device[%d] Disassociations %d \n", i, ps->cli_Disassociations));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Device[%d] AuthenticationFailures %d \n", i, ps->cli_AuthenticationFailures));
        } // end of For Loop

        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,************Device Data Ends************* \n"));
        if ( ServiceType == PUBLIC )
            print_list( headnodepublic );
        else
            print_list( headnodeprivate );

    } // end of if statement
    else
    {
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : wifi_getApAssociatedDeviceDiagnosticResult Return[%d] array_size [%d] \n",__FUNCTION__, ret, array_size));
    } 

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT \n", __FUNCTION__ ));
    return ret;
}

void* StartAssociatedDeviceHarvesting( void *arg )
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER \n", __FUNCTION__ ));
    CcspHarvesterEventTrace(("RDK_LOG_DEBUG, Harvester %s : Started Thread to start DeviceData Harvesting  \n", __FUNCTION__ ));

    int ret = 0;
    ULONG uDefaultVal = 0;

    currentReportingPeriod = GetIDWReportingPeriod();

    if(GetIDWOverrideTTL() <  currentReportingPeriod)
    {
        SetIDWOverrideTTL(currentReportingPeriod);
    }

    while (!ret && GetIDWHarvestingStatus()) {

        ULONG output = 0;
        int k = 0;
        /* CID: 79303 OVERRUN - Out-of-bounds access
         * qtn-wifi component access the max buffer size as 512 bytes*/
        char ssid[STR_BUF_MAX] = {0};
        int ret =  wifi_getSSIDNumberOfEntries(&output); //Tr181

        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Number of SSID Entries = %ld ReturnValue [%d]\n", output, ret));

        if (!ret && output > 0)
        {
            // scan PRIVATE WiFi
            for (k = PRIVATE_WIFI_IDX_STARTS; k <= PRIVATE_WIFI_IDX_ENDS; k++)
            {
                CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, PRIVATE WiFi, Idx = %d\n", k ));
                ret = wifi_getSSIDName(k, ssid);
                if (ret)
                {
                    CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : wifi_getSSIDName returned error [%d] \n",__FUNCTION__,  ret));
                }

                ret = GetWiFiApGetAssocDevicesData(PRIVATE, k, ssid);
                if (ret)
                {
                    CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : GetWiFiApGetAssocDevicesData returned error [%d] for SSID[%s] \n",__FUNCTION__, ret, ssid));
                }
            }

            // scan PUBLIC WiFi
            for (k = PUBLIC_WIFI_IDX_STARTS; k <= PUBLIC_WIFI_IDX_ENDS; k++)
            {
                CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, PUBLIC WiFi, Idx = %d\n", k ));
                ret = wifi_getSSIDName(k, ssid);
                if (ret)
                {
                    CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : wifi_getSSIDName returned error [%d] \n",__FUNCTION__,  ret));
                }

                ret = GetWiFiApGetAssocDevicesData(PUBLIC, k, ssid);
                if (ret)
                {
                    CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : GetWiFiApGetAssocDevicesData returned error [%d] for SSID[%s] \n",__FUNCTION__, ret, ssid));
                }
            }

            currentReportingPeriod = currentReportingPeriod + GetIDWPollingPeriod();
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Before Sending to WebPA and AVRO currentReportingPeriod [%ld] GetIDWReportingPeriod()[%ld]  \n", currentReportingPeriod, GetIDWReportingPeriod()));

            if (currentReportingPeriod >= GetIDWReportingPeriod())
            {
                //struct associateddevicedata* ptr = headnodeprivate;
                if( headnodeprivate )
                    {
                        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Before Sending to WebPA and AVRO IDWReportingPeriod[%ld]  \n", GetIDWReportingPeriod()));
                        harvester_report_associateddevices( headnodeprivate, "PRIVATE");
                        delete_list( headnodeprivate );
                        headnodeprivate = NULL;
                    }

                //ptr = headnodepublic;
                if( headnodepublic )
                    {
                        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Before Sending to WebPA and AVRO IDWReportingPeriod[%ld]  \n", GetIDWReportingPeriod()));
                        harvester_report_associateddevices( headnodepublic, "PUBLIC");
                        delete_list( headnodepublic );
                        headnodepublic = NULL;
                    }

                currentReportingPeriod = 0;
            }

            if(!GetIDWOverrideTTL())
            {
                //Polling
                uDefaultVal = GetIDWPollingPeriodDefault();
                SetIDWPollingPeriod( uDefaultVal );
                //RDKB-9258 : Saving polling period to NVRAM.
                SetIDWPollingPeriodInNVRAM( uDefaultVal );

                //Reporting
                uDefaultVal = GetIDWReportingPeriodDefault(); 
                SetIDWReportingPeriod( uDefaultVal );
                //RDKB-9258 : Saving reporting period to NVRAM.
                SetIDWReportingPeriodInNVRAM( uDefaultVal );

                //TTL
                SetIDWOverrideTTL(GetIDWOverrideTTLDefault());
            }

            if(GetIDWOverrideTTL())
            {
                SetIDWOverrideTTL(GetIDWOverrideTTL() - GetIDWPollingPeriod());
            }

            WaitForPthreadConditionTimeoutIDW();

        }
        else
        {
            CcspHarvesterTrace(("RDK_LOG_DEBUG, wifi_getSSIDNumberOfEntries Error [%d] or No SSID [%ld] \n", ret, output));
        }

        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,GetIDWPollingPeriod[%ld]\n", GetIDWPollingPeriod()));
    }

    harvester_avro_cleanup();    
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT \n", __FUNCTION__ ));
    CcspHarvesterEventTrace(("RDK_LOG_DEBUG, Harvester %s : Thread Stopped DeviceData Harvesting  \n", __FUNCTION__ ));

    return NULL;
}

// End of File

