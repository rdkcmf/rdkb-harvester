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
#include "harvester_radio_traffic.h"
#include "harvester_avro.h"
#include "ccsp_harvesterLog_wrapper.h"
#include "report_common.h"
#include "safec_lib_common.h"
#include "harvester_associated_devices.h"
#include "secure_wrapper.h"
#ifdef RDK_ONEWIFI
#include "harvester_rbus_api.h"
#endif

ULONG RISReportingPeriodDefault = DEFAULT_POLLING_INTERVAL;
ULONG RISPollingPeriodDefault = DEFAULT_REPORTING_INTERVAL;

ULONG RISReportingPeriod = DEFAULT_REPORTING_INTERVAL;
ULONG RISPollingPeriod = DEFAULT_POLLING_INTERVAL;

ULONG currentRISReportingPeriod = 0;

BOOL RISHarvesterStatus = FALSE;
ULONG RISOverrideTTL = 300;
ULONG RISOverrideTTLDefault = 300;

char RadioBSSID[MAX_NUM_RADIOS][19] = {{0}};

#ifdef RDK_ONEWIFI
char bufferRIR[72] = {'\0'};
#endif

static pthread_mutex_t risMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t risCond = PTHREAD_COND_INITIALIZER;

ULONG RadioTrafficPeriods[13] = {1,5,15,30,60,300,900,1800,3600,10800,21600,43200,86400};

BOOL isvalueinRISarray(ULONG val, ULONG *arr, int size);

void* StartRadioTrafficHarvesting( void *arg );
void _rtsyscmd(FILE *f, char *retBuf, int retBufSize);
int setRISCurrentTimeFromDmCli();
int add_to_rt_list(int radioIndex, BOOL enabled, char* freqband, ULONG channel, char* opchanbw, wifi_radioTrafficStats2_t* radiotrafficdata);
void print_rt_list();
void delete_rt_list();
int GetRadioTrafficData(int radioIndex);
extern void rt_avro_cleanup();
extern ulong GetCurrentTimeInSecond();
#if !defined(UTC_ENABLE_ATOM) && !defined(_HUB4_PRODUCT_REQ_)
extern int getTimeOffsetFromUtc();
#endif

static struct radiotrafficdata rIndex[MAX_NUM_RADIOS];

// RDKB-9258 : set polling and reporting periods to NVRAM after TTL expiry
extern ANSC_STATUS SetRISPollingPeriodInNVRAM(ULONG pPollingVal);
extern ANSC_STATUS SetRISReportingPeriodInNVRAM(ULONG pReportingVal);

static void WaitForPthreadConditionTimeoutRIS()
{
    struct timespec _ts = { 0 };
    struct timespec _now = { 0 };
    int n;


    pthread_mutex_lock(&risMutex);

    clock_gettime(CLOCK_REALTIME, &_now);
    _ts.tv_sec = _now.tv_sec + GetRISPollingPeriod();

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : Waiting for %lu sec\n",__FUNCTION__,GetRISPollingPeriod()));

    n = pthread_cond_timedwait(&risCond, &risMutex, &_ts);
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

    pthread_mutex_unlock(&risMutex);

}

BOOL isvalueinRISarray(ULONG val, ULONG *arr, int size)
{
    int i;
    for (i=0; i < size; i++) {
        if (arr[i] == val)
            return true;
    }
    return false;
}


int SetRISHarvestingStatus(BOOL status)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s  Old[%d] New[%d] \n", __FUNCTION__, RISHarvesterStatus, status ));

    if (RISHarvesterStatus != status)
        RISHarvesterStatus = status;
    else
        return 0;

    if (RISHarvesterStatus)
    {
        pthread_t tid;
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s Starting Thread to start RadioTraffic Data Harvesting  \n", __FUNCTION__ ));
        if (pthread_create(&tid, NULL, StartRadioTrafficHarvesting, NULL))
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : Failed to Start Thread to start RadioTraffic Harvesting  \n", __FUNCTION__ ));
            return ANSC_STATUS_FAILURE;
        }
    }
    else
    {
        int ret;
        pthread_mutex_lock(&risMutex);
        ret = pthread_cond_signal(&risCond);
        pthread_mutex_unlock(&risMutex);
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

BOOL GetRISHarvestingStatus()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT RISHarvesterStatus[%d] \n", __FUNCTION__, RISHarvesterStatus ));
    return RISHarvesterStatus;
}

int SetRISReportingPeriod(ULONG interval)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT Old[%lu] New[%lu] \n", __FUNCTION__, RISReportingPeriod, interval ));
    RISReportingPeriod = interval;
    SetRISOverrideTTL(2*RISReportingPeriod);
    return 0;
}

ULONG GetRISReportingPeriod()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT RISReportingPeriod[%lu] \n", __FUNCTION__, RISReportingPeriod ));    
    return RISReportingPeriod;
}

int SetRISPollingPeriod(ULONG interval)
{
    int ret;
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT Old[%lu] New[%lu] \n", __FUNCTION__, RISPollingPeriod, interval ));    
    RISPollingPeriod = interval;

    pthread_mutex_lock(&risMutex);
    currentRISReportingPeriod = GetRISReportingPeriod();

    ret = pthread_cond_signal(&risCond);
    pthread_mutex_unlock(&risMutex);
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

BOOL ValidateRISPeriod(ULONG interval)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    BOOL ret = FALSE;
    ret = isvalueinarray(interval, RadioTrafficPeriods, sizeof(RadioTrafficPeriods)/sizeof(RadioTrafficPeriods[ 0 ]));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT RET[%d] \n", __FUNCTION__ , ret ));
    return ret;    
} 

ULONG GetRISPollingPeriod()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT RISReportingPeriod[%lu] \n", __FUNCTION__, RISPollingPeriod ));
    return RISPollingPeriod;
}

int SetRISReportingPeriodDefault(ULONG interval)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT Old[%lu] New[%lu] \n", __FUNCTION__, RISReportingPeriodDefault, interval ));   
    RISReportingPeriodDefault = interval;
    return 0;
}

ULONG GetRISReportingPeriodDefault()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT RISReportingPeriodDefault[%lu] \n", __FUNCTION__, RISReportingPeriodDefault ));  
    return RISReportingPeriodDefault;
}

int SetRISPollingPeriodDefault(ULONG interval)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT Old[%lu] New[%lu] \n", __FUNCTION__, RISPollingPeriodDefault, interval )); 
    RISPollingPeriodDefault = interval;
    return 0;
}

ULONG GetRISPollingPeriodDefault()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT RISPollingPeriodDefault[%lu \n", __FUNCTION__, RISPollingPeriodDefault ));  
    return RISPollingPeriodDefault;
}

ULONG GetRISOverrideTTL()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT RISOverrideTTL[%lu] \n", __FUNCTION__, RISOverrideTTL ));  
    return RISOverrideTTL;
}

int SetRISOverrideTTL(ULONG count)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT Old[%lu] New[%lu] \n", __FUNCTION__, RISOverrideTTL, count ));
    RISOverrideTTL = count;
    return 0;
}

ULONG GetRISOverrideTTLDefault()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT RISOverrideTTLDefault[%lu] \n", __FUNCTION__, RISOverrideTTLDefault ));    
    return RISOverrideTTLDefault;
}

void _rtsyscmd(FILE *f, char *retBuf, int retBufSize)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));

    char *ptr = retBuf;
    int bufSize = retBufSize, bufbytes = 0, readbytes = 0;

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

    retBuf[retBufSize - 1] = 0;

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT\n", __FUNCTION__ ));
}

int getRadioBssid(int radioIndex, char* radio_BSSID)
{
    int ret = 0;
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));

    if(strlen(radio_BSSID) == 0)
    {
#if defined(_XB6_PRODUCT_REQ_) && !defined(_XB7_PRODUCT_REQ_)
    char radioIfName[128] = {0};
    int ssidIndex = (radioIndex == 0) ? 1 : 0;
    #ifdef RDK_ONEWIFI
         snprintf(bufferRIR, sizeof(bufferRIR), "Device.WiFi.SSID.%d.BSSID", ssidIndex+1);
         ret = rbus_getStringValue((char*)&radioIfName, bufferRIR);
    #else
         ret = wifi_getSSIDMACAddress(ssidIndex, radioIfName);
    #endif
    if (ret)
    {
       CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : wifi_getSSIDMACAddress returned error [%d] \n",__FUNCTION__ , ret));
    }
#else
        char radioIfName[128] = {0};
        FILE *f = NULL;
        #ifdef RDK_ONEWIFI
             snprintf(bufferRIR, sizeof(bufferRIR), "Device.WiFi.Radio.%d.Name", radioIndex+1);
             ret = rbus_getStringValue((char*)&radioIfName, bufferRIR);
        #else
             ret = wifi_getRadioIfName(radioIndex, radioIfName);
        #endif

        if (ret)
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : wifi_getRadioIfName returned error [%d] \n",__FUNCTION__ , ret));
        }
        else
        {
            f = v_secure_popen("r","ifconfig -a %s | grep HWaddr | awk '{print $5}' | cut -c -17", radioIfName);
            if(f == NULL)
            {
                CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : Error opening popen pipe ! \n",__FUNCTION__));
                return -1;
            }           
	    _rtsyscmd(f, radio_BSSID, 19);
            ret = v_secure_pclose(f);
            if(ret != 0)
            {
                CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : Error closing command pipe! ret : [%d] \n",__FUNCTION__ , ret));
            }
        }
#endif
    }
    else
    {
        CcspHarvesterTrace(("RDK_LOG_DEBUG, Array already contains the value [%s] \n", radio_BSSID));
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT\n", __FUNCTION__ ));

    return ret;                      

}

int add_to_rt_list(int radioIndex, BOOL enabled, char* freqband, ULONG channel, char* opchanbw, wifi_radioTrafficStats2_t* radiotrafficdata)
{
    int ret = 0;
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER \n", __FUNCTION__ ));

    ret = getRadioBssid(radioIndex, (char*) &RadioBSSID[radioIndex]);
    if (ret)
    {
        /* Coverity Fix CID: 124997  PRINTF_ARGS */
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : Radio %d does not have a valid BSSID  or ERROR retured %d \n",__FUNCTION__ , radioIndex, ret));
        return ret;
    }

    rIndex[radioIndex].radioBssid = strdup((char*)&RadioBSSID[radioIndex]);
    rIndex[radioIndex].enabled = enabled;
    rIndex[radioIndex].rtdata = radiotrafficdata;
    rIndex[radioIndex].radioOperatingFrequencyBand = strdup(freqband);
    rIndex[radioIndex].radiOperatingChannelBandwidth = strdup(opchanbw);
    rIndex[radioIndex].radioChannel = channel;
    gettimeofday(&(rIndex[radioIndex].timestamp), NULL);
#if !defined(UTC_ENABLE_ATOM) && !defined(_HUB4_PRODUCT_REQ_)	
    rIndex[radioIndex].timestamp.tv_sec -= getTimeOffsetFromUtc();
#endif


    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT \n", __FUNCTION__ ));

    return ret;
}

void print_rt_list()
{
    int z = 0;
    int ret = 0;
    ULONG radio_num = 0;

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER \n", __FUNCTION__ ));
    #ifdef RDK_ONEWIFI
           ret = rbus_getUInt32Value(&radio_num, "Device.WiFi.RadioNumberOfEntries");
    #else
           ret =  wifi_getRadioNumberOfEntries(&radio_num);
    #endif
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Number of Radio Entries = %ld ReturnValue [%d]\n", radio_num, ret));

    for(z = 0; z < radio_num; z++)
    {
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, TimeStamp[%d] for Node[%d] with RadioBSSID[%s] \n", (int)rIndex[z].timestamp.tv_sec, z, (rIndex[z].radioBssid != NULL)?rIndex[z].radioBssid:"radioBssid is NULL"));
    }
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT \n", __FUNCTION__ ));
    return;
}

void delete_rt_list()
{
    int i = 0;
    int ret = 0;
    ULONG radio_num = 0;
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER \n", __FUNCTION__ ));

    #ifdef RDK_ONEWIFI
           ret = rbus_getUInt32Value(&radio_num, "Device.WiFi.RadioNumberOfEntries");
    #else
           ret =  wifi_getRadioNumberOfEntries(&radio_num);
    #endif
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Number of Radio Entries = %ld ReturnValue [%d]\n", radio_num, ret));

    for(i = 0; i < radio_num; i++)
    {
        if((rIndex[i].radioBssid) != NULL)
        {
	    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, with radioName[%s] \n", rIndex[i].radioBssid));
            free(rIndex[i].radioBssid);
        }
        if((rIndex[i].radioOperatingFrequencyBand) != NULL)
        {
            free(rIndex[i].radioOperatingFrequencyBand);
        }
        if((rIndex[i].radiOperatingChannelBandwidth) != NULL)
        {
            free(rIndex[i].radiOperatingChannelBandwidth);
        }
        if((rIndex[i].rtdata) != NULL)
        {
            free(rIndex[i].rtdata);
        }
        rIndex[i].radioBssid = NULL;
        rIndex[i].radioOperatingFrequencyBand = NULL;
        rIndex[i].radiOperatingChannelBandwidth = NULL;
        rIndex[i].rtdata = NULL;
        memset(&rIndex[i], 0, sizeof(struct radiotrafficdata));
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT \n", __FUNCTION__ ));

    return;
}

int GetRadioTrafficData(int radioIndex)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER \n", __FUNCTION__ ));

    BOOL enabled = FALSE;
    wifi_radioTrafficStats2_t *radio_traffic_stats=NULL;
    ULONG channel = 0;
    char freqband[128] = {0};
    char opchanbw[128] = {0};
    int ret = 0;

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Radio Index is %d \n", radioIndex));

    #ifdef RDK_ONEWIFI
          snprintf(bufferRIR, sizeof(bufferRIR), "Device.WiFi.Radio.%d.Enable", radioIndex+1);
          ret = rbus_getBoolValue(&enabled,  bufferRIR);
    #else
          ret = wifi_getRadioEnable(radioIndex, &enabled);
    #endif
    if (ret)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s :  Radio %d is NOT ENABLED  or ERROR retured %d \n",__FUNCTION__ , radioIndex, ret));
        return ret;
    }

    #ifdef RDK_ONEWIFI
          snprintf(bufferRIR, sizeof(bufferRIR), "Device.WiFi.Radio.%d.Channel", radioIndex+1);
          ret = rbus_getUInt32Value(&channel, bufferRIR);
    #else
          ret = wifi_getRadioChannel(radioIndex, &channel);
    #endif
    if (ret)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : radioIndex[%d] channel [%ld] \n", __FUNCTION__ , radioIndex, channel));
        return ret;
    }

    #ifdef RDK_ONEWIFI
         snprintf(bufferRIR, sizeof(bufferRIR), "Device.WiFi.Radio.%d.OperatingFrequencyBand", radioIndex+1);
         ret = rbus_getStringValue((char*)&freqband, bufferRIR);
    #else
         ret = wifi_getRadioOperatingFrequencyBand(radioIndex, (char*)&freqband);
    #endif
    if (ret)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s :  radioIndex[%d] freqband [%s] \n",__FUNCTION__ , radioIndex, freqband));
        return ret;
    }

    #ifdef RDK_ONEWIFI
         snprintf(bufferRIR, sizeof(bufferRIR), "Device.WiFi.Radio.%d.OperatingChannelBandwidth", radioIndex+1);
         ret = rbus_getStringValue((char*)&opchanbw, bufferRIR);
    #else
         ret = wifi_getRadioOperatingChannelBandwidth(radioIndex, (char*)&opchanbw);
    #endif
    if (ret)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : radioIndex[%d] opchanbw [%s] \n",__FUNCTION__ , radioIndex, opchanbw));
        return ret;
    }


    radio_traffic_stats = (wifi_radioTrafficStats2_t*) malloc(sizeof(wifi_radioTrafficStats2_t));
    #ifdef RDK_ONEWIFI
        ret = rbus_wifi_getRadioTrafficStats2(radioIndex+1, radio_traffic_stats);
    #else
        ret = wifi_getRadioTrafficStats2(radioIndex, radio_traffic_stats);
    #endif
    if(( 0 == ret ) && ( NULL != radio_traffic_stats ) )
    {
        ret = add_to_rt_list( radioIndex,  enabled, freqband, channel, opchanbw, radio_traffic_stats);
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, ************RadioTraffic Data Begins************* \n"));

        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] ENABLED [%d] \n", radioIndex, enabled));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] channel [%ld] \n", radioIndex, channel));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] freqband [%s] \n", radioIndex, freqband));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] opchanbw [%s] \n", radioIndex, opchanbw));

        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] radio_BytesSent [%lu] \n", radioIndex, radio_traffic_stats->radio_BytesSent));  
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] radio_BytesReceived [%lu] \n", radioIndex, radio_traffic_stats->radio_BytesReceived));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] radio_PacketsSent [%lu] \n", radioIndex, radio_traffic_stats->radio_PacketsSent));  
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] radio_PacketsReceived [%lu] \n", radioIndex, radio_traffic_stats->radio_PacketsReceived));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] radio_ErrorsSent [%lu] \n", radioIndex, radio_traffic_stats->radio_ErrorsSent));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] radio_ErrorsReceived [%lu] \n", radioIndex, radio_traffic_stats->radio_ErrorsReceived));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] radio_DiscardPacketsSent [%lu] \n", radioIndex, radio_traffic_stats->radio_DiscardPacketsSent));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] radio_DiscardPacketsReceived [%lu] \n", radioIndex, radio_traffic_stats->radio_DiscardPacketsReceived)); 
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] radio_PLCPErrorCount [%lu] \n", radioIndex, radio_traffic_stats->radio_PLCPErrorCount));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] radio_FCSErrorCount [%lu] \n", radioIndex, radio_traffic_stats->radio_FCSErrorCount));  
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] radio_InvalidMACCount [%lu] \n", radioIndex, radio_traffic_stats->radio_InvalidMACCount));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] radio_PacketsOtherReceived [%lu] \n", radioIndex, radio_traffic_stats->radio_PacketsOtherReceived));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] radio_NoiseFloor [%d] \n", radioIndex, radio_traffic_stats->radio_NoiseFloor));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] radio_ChannelUtilization [%lu] \n", radioIndex, radio_traffic_stats->radio_ChannelUtilization));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] radio_ActivityFactor [%d] \n", radioIndex, radio_traffic_stats->radio_ActivityFactor)); 
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] radio_CarrierSenseThreshold_Exceeded [%d] \n", radioIndex, radio_traffic_stats->radio_CarrierSenseThreshold_Exceeded));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] radio_RetransmissionMetirc [%d] \n", radioIndex, radio_traffic_stats->radio_RetransmissionMetirc)); 
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] radio_MaximumNoiseFloorOnChannel [%d] \n", radioIndex, radio_traffic_stats->radio_MaximumNoiseFloorOnChannel));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] radio_MinimumNoiseFloorOnChannel [%d] \n", radioIndex, radio_traffic_stats->radio_MinimumNoiseFloorOnChannel)); 
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] radio_MedianNoiseFloorOnChannel [%d] \n", radioIndex, radio_traffic_stats->radio_MedianNoiseFloorOnChannel));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,Radio[%d] radio_StatisticsStartTime [%lu] \n", radioIndex, radio_traffic_stats->radio_StatisticsStartTime));

        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,************RadioTraffic Data Ends************* \n"));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,***************************************** \n"));
        
        print_rt_list();

    } // end of if statement
    else
    {
        //Free allocated memory when failure case
        if( NULL != radio_traffic_stats )
        {
            free(radio_traffic_stats);
            radio_traffic_stats = NULL;
        }

        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : wifi_getRadioTrafficStats2 Return[%d] \n",__FUNCTION__ , ret));
    } 

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT \n", __FUNCTION__ ));

    return ret;
}

void* StartRadioTrafficHarvesting( void *arg )
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER \n", __FUNCTION__ ));
    CcspHarvesterEventTrace(("RDK_LOG_DEBUG, Harvester %s Starting Thread to start RadioTraffic Data Harvesting  \n", __FUNCTION__ ));

    int ret = 0;
    ULONG uDefaultVal = 0;
    static int retry_count = 0;

    currentRISReportingPeriod = GetRISReportingPeriod();

    if(GetRISOverrideTTL() <  currentRISReportingPeriod)
    {
        SetRISOverrideTTL(currentRISReportingPeriod);
    }

    while (!ret && GetRISHarvestingStatus()) {

        ULONG output = 0;
        int k = 0;

    #ifdef RDK_ONEWIFI
           ret = rbus_getUInt32Value(&output, "Device.WiFi.RadioNumberOfEntries");
    #else
           ret =  wifi_getRadioNumberOfEntries(&output); //Tr181
    #endif

        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Number of Radio Entries = %ld ReturnValue [%d]\n", output, ret));
        if (!ret && output > 0)
        {
            retry_count = 0;

            for (k = 0; k < output; k++)
            {
                ret = GetRadioTrafficData(k);
                if (ret)
                {
                    CcspHarvesterTrace(("RDK_LOG_ERROR, GetRadioRadioTrafficData returned error [%d] for radioIndex[%d] \n", ret, k));
                }
            }

            currentRISReportingPeriod = currentRISReportingPeriod + GetRISPollingPeriod();
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, currentRISReportingPeriod[%ld]\n", currentRISReportingPeriod));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, GetRISReportingPeriod()[%ld]\n", GetRISReportingPeriod()));

            if (currentRISReportingPeriod >= GetRISReportingPeriod())
            {
                {
                    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,  Before Sending to WebPA and AVRO RISReportingPeriod[%ld]  \n", GetRISReportingPeriod()));
                    harvester_report_radiotraffic(rIndex);
                    delete_rt_list();
                }

                currentRISReportingPeriod = 0;
            }

            if(!GetRISOverrideTTL())
            {
                //Polling
                uDefaultVal = GetRISPollingPeriodDefault();
                SetRISPollingPeriod( uDefaultVal );
                //RDKB-9258 : Saving polling period to NVRAM.
                SetRISPollingPeriodInNVRAM( uDefaultVal );

                //Reporting
                uDefaultVal = GetRISReportingPeriodDefault();
                SetRISReportingPeriod( uDefaultVal );
                //RDKB-9258 : Saving reporting period to NVRAM.
                SetRISReportingPeriodInNVRAM( uDefaultVal );

                //TTL
                SetRISOverrideTTL(GetRISOverrideTTLDefault());
            }

            if(GetRISOverrideTTL())
            {
                SetRISOverrideTTL(GetRISOverrideTTL() - GetRISPollingPeriod());
            }

            WaitForPthreadConditionTimeoutRIS();

        }
        else
        {
            CcspHarvesterTrace(("RDK_LOG_WARN, wifi_getRadioNumberOfEntries Error [%d] or No SSID [%ld] \n", ret, output));
            retry_count++;
            if( retry_count == 3)
            {
                CcspHarvesterTrace(("RDK_LOG_WARN, Max retry reached for wifi_getRadioNumberOfEntries\n"));
                WaitForPthreadConditionTimeoutRIS();
                retry_count = 0;
            }
        }

        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, GetRISPollingPeriod[%ld]\n", GetRISPollingPeriod()));
    }

    SetRISHarvestingStatus(FALSE);
    rt_avro_cleanup();
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT \n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s Stopped Thread for RadioTraffic Data Harvesting  \n", __FUNCTION__ ));

    return NULL; // shouldn't return;
}

// End of File

