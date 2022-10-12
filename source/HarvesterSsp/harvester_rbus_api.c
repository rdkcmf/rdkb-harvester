/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2022 RDK Management
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
/**
 * @file harvester_rbus_api.c
 *
 * @ To replace the WiFi HAL calls with RBUS API, when 'OneWifi' is enabled.
 *
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
#include <stdbool.h>
#include <semaphore.h>
#include "ccsp_harvesterLog_wrapper.h"
#include "report_common.h"
#include "safec_lib_common.h"
#include "secure_wrapper.h"
#include "harvester_rbus_api.h"

static rbusHandle_t rbus_handle;

rbusHandle_t get_rbus_handle(void)
{
    return rbus_handle;
}

bool rbusInitializedCheck()
{
    return rbus_handle != NULL ? true : false;
}

int harvesterRbusInit(const char *pComponentName)
{
    int ret = RBUS_ERROR_SUCCESS;
    CcspHarvesterTrace(("RDK_LOG_INFO, rbus_open for component %s\n", pComponentName));

    ret = rbus_open(&rbus_handle, pComponentName);

    if(ret != RBUS_ERROR_SUCCESS)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s: failed with error code %d\n", __FUNCTION__, ret));
        return 1;
    }

    CcspHarvesterTrace(("RDK_LOG_INFO, Harvester %s: is success. ret is %d\n", __FUNCTION__, ret));
    return 0;
}

void harvesterRbus_Uninit()
{
    rbus_close(rbus_handle);
}

int rbus_getBoolValue(BOOL * value, char * path)
{
    int rc = 0;
    rbusValue_t boolVal = NULL;

    if(!rbusInitializedCheck())
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s: rbus_open failed\n", __FUNCTION__));
        return 1;
    }

    CcspHarvesterTrace(("RDK_LOG_DEBUG, Harvester %s: calling rbus get for %s\n", __FUNCTION__, path));

    rc = rbus_get(rbus_handle, path, &boolVal);

    if(rc != RBUS_ERROR_SUCCESS)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s: rbus_get failed for [%s] with error [%d]\n",  __FUNCTION__, path, rc));
        if(boolVal != NULL)
        {
            rbusValue_Release(boolVal);
        }
        return 1;
    }

    *value = rbusValue_GetBoolean(boolVal);
    CcspHarvesterTrace(("RDK_LOG_DEBUG, Harvester %s: the value of %s is %s\n", __FUNCTION__, path, *value ? "true" : "false"));
    rbusValue_Release(boolVal);
    return 0;
}

int rbus_getStringValue(char * value, char * path)
{
    int rc = 0;
    rbusValue_t strVal = NULL;

    if(!rbusInitializedCheck())
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s: rbus_open failed\n", __FUNCTION__));
        return 1;
    }

    CcspHarvesterTrace(("RDK_LOG_DEBUG, Harvester %s: calling rbus get for %s\n", __FUNCTION__, path));

    rc = rbus_get(rbus_handle, path, &strVal);

    if(rc != RBUS_ERROR_SUCCESS)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s: rbus_get failed for [%s] with error [%d]\n", __FUNCTION__, path, rc));
        if(strVal != NULL)
        {
            rbusValue_Release(strVal);
        }
        return 1;
    }

    snprintf(value, 128, (char *)rbusValue_GetString(strVal, NULL));
    CcspHarvesterTrace(("RDK_LOG_DEBUG, Harvester %s: the value for %s is %s\n", __FUNCTION__, path, value));
    rbusValue_Release(strVal);
    return 0;
}

int rbus_getUInt32Value(ULONG * value, char * path)
{
    int rc = 0;
    rbusValue_t uintVal = NULL;

    if(!rbusInitializedCheck())
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s: rbus_open failed\n", __FUNCTION__));
        return 1;
    }

    CcspHarvesterTrace(("RDK_LOG_DEBUG, Harvester %s: calling rbus get for %s\n", __FUNCTION__, path));

    rc = rbus_get(rbus_handle, path, &uintVal);

    if(rc != RBUS_ERROR_SUCCESS)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s: rbus_get failed for [%s] with error [%d]\n",  __FUNCTION__, path, rc));
        if(uintVal != NULL)
        {
            rbusValue_Release(uintVal);
        }
        return 1;
    }

    *value = rbusValue_GetUInt32(uintVal);
    CcspHarvesterTrace(("RDK_LOG_DEBUG, Harvester %s: the value for %s is %lu\n", __FUNCTION__, path, *value));
    rbusValue_Release(uintVal);
    return 0;
}

int rbus_getApAssociatedDeviceDiagnosticResult(int index, wifi_associated_dev_t** associated_dev, uint32_t *assocDevCount)
{
    int rc, resCount, count = 0;
    wifi_associated_dev_t *dev=NULL;
    rbusValue_t assocDevVal;
    rbusProperty_t props = NULL;
    rbusValue_t paramValue_t = NULL;

    if(!rbusInitializedCheck())
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s: rbus_open failed\n", __FUNCTION__));
        return 1;
    }

    char path[128] = {'\0'};
    snprintf(path, sizeof(path), "Device.WiFi.AccessPoint.%d.AssociatedDeviceNumberOfEntries", index);

    CcspHarvesterTrace(("RDK_LOG_DEBUG, Harvester %s: calling rbus get for %s\n", __FUNCTION__, path));

    rc = rbus_get(rbus_handle, path, &assocDevVal);

    if(rc != RBUS_ERROR_SUCCESS)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s: rbus_get failed for [%s] with error [%d]\n", __FUNCTION__, path, rc));
        if(assocDevVal != NULL)
        {
            rbusValue_Release(assocDevVal);
        }
        return 1;
    }

    *assocDevCount = rbusValue_GetUInt32(assocDevVal);

    if(*assocDevCount == 0)
    {
        CcspHarvesterTrace(("RDK_LOG_INFO, Harvester %s: no associated devices are connected\n", __FUNCTION__));
        return 0;
    }

    dev = (wifi_associated_dev_t *)calloc(*assocDevCount, sizeof(wifi_associated_dev_t));
    *associated_dev = dev;

    const char * wildCardPath[1];
    wildCardPath[0] = path;

    for(count = 0; count < *assocDevCount; count++)
    {
        snprintf(path, sizeof(path), "Device.WiFi.AccessPoint.%d.AssociatedDevice.%d.", index, count+1);

        CcspHarvesterTrace(("RDK_LOG_DEBUG, Harvester %s: calling rbus get for %s\n", __FUNCTION__, path));

        rc = rbus_getExt(rbus_handle, 1, wildCardPath, &resCount, &props);

        if(rc != RBUS_ERROR_SUCCESS)
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s: rbus_getExt failed for [%s] with error [%d]\n", __FUNCTION__, path, rc));
            rbusProperty_Release(props);
            return 1;
        }

        if(props != NULL)
        {
            rbusProperty_t next = props;
            while(next != NULL)
            {
                paramValue_t = rbusProperty_GetValue(next);
                if(paramValue_t != NULL)
                {
                    char * propName = (char *)rbusProperty_GetName(next);
                    if(propName != NULL)
                    {
                        CcspHarvesterTrace(("RDK_LOG_DEBUG, propName is %s\n", propName));
                        if(strstr(propName, ".MACAddress") != NULL)
                        {
                            char * mac = (char *)rbusValue_GetString(paramValue_t, NULL);
                            if(mac != NULL)
                            {
                                sscanf(mac, "%x:%x:%x:%x:%x:%x",
                                (unsigned int *)&dev[count].cli_MACAddress[0],
                                (unsigned int *)&dev[count].cli_MACAddress[1],
                                (unsigned int *)&dev[count].cli_MACAddress[2],
                                (unsigned int *)&dev[count].cli_MACAddress[3],
                                (unsigned int *)&dev[count].cli_MACAddress[4],
                                (unsigned int *)&dev[count].cli_MACAddress[5]);
                            }
                        }
                        else if(strstr(propName, ".AuthenticationState") != NULL)
                        {
                            bool authState = rbusValue_GetBoolean(paramValue_t);
                            dev[count].cli_AuthenticationState = authState;
                        }
                        else if(strstr(propName, ".LastDataDownlinkRate") != NULL)
                        {
                            uint32_t lstDataDwnRate = rbusValue_GetUInt32(paramValue_t);
                            dev[count].cli_LastDataDownlinkRate = lstDataDwnRate;
                        }
                        else if(strstr(propName, ".LastDataUplinkRate") != NULL)
                        {
                            uint32_t lstDataUpRate = rbusValue_GetUInt32(paramValue_t);
                            dev[count].cli_LastDataUplinkRate = lstDataUpRate;
                        }
                        else if(strstr(propName, ".SignalStrength") != NULL)
                        {
                            int signalStrength  = rbusValue_GetInt32(paramValue_t);
                            dev[count].cli_SignalStrength = signalStrength;
                        }
                        else if(strstr(propName, ".Retransmissions") != NULL)
                        {
                            uint32_t retransmission = rbusValue_GetUInt32(paramValue_t);
                            dev[count].cli_Retransmissions = retransmission;
                        }
                        else if(strstr(propName, ".Active") != NULL)
                        {
                            bool active  = rbusValue_GetBoolean(paramValue_t);
                            dev[count].cli_Active = active;
                        }
                        else if(strstr(propName, ".X_COMCAST-COM_OperatingStandard") != NULL)
                        {
                            char * operatingStd=(char*)rbusValue_GetString(paramValue_t, NULL);
                            if(operatingStd != NULL)
                            {
                                strcpy_s(dev[count].cli_OperatingStandard, 64, operatingStd);
                            }
                        }
                        else if(strstr(propName, ".X_COMCAST-COM_OperatingChannelBandwidth") != NULL)
                        {
                            char * opchanBtw=(char*)rbusValue_GetString(paramValue_t, NULL);
                            if(opchanBtw != NULL)
                            {
                                strcpy_s(dev[count].cli_OperatingChannelBandwidth, 64, opchanBtw);
                            }
                        }
                        else if(strstr(propName, ".X_COMCAST-COM_SNR") != NULL)
                        {
                            int snr  = rbusValue_GetInt32(paramValue_t);
                            dev[count].cli_SNR = snr;
                        }
                        else if(strstr(propName, ".X_COMCAST-COM_InterferenceSources") != NULL)
                        {
                            char * interferenceSrc = (char*)rbusValue_GetString(paramValue_t, NULL);
                            if(interferenceSrc != NULL)
                            {
                                strcpy_s(dev[count].cli_InterferenceSources, 64, interferenceSrc);
                            }
                        }
                        else if(strstr(propName, ".X_COMCAST-COM_DataFramesSentAck") != NULL)
                        {
                            uint32_t datFrameSentACK = rbusValue_GetUInt32(paramValue_t);
                            dev[count].cli_DataFramesSentAck = datFrameSentACK;
                        }
                        else if(strstr(propName, ".X_COMCAST-COM_DataFramesSentNoAck") != NULL)
                        {
                            uint32_t datFrameSentNACK= rbusValue_GetUInt32(paramValue_t);
                            dev[count].cli_DataFramesSentNoAck = datFrameSentNACK;
                        }
                        else if(strstr(propName, ".X_COMCAST-COM_BytesSent") != NULL)
                        {
                            uint32_t  bytesSent= rbusValue_GetUInt32(paramValue_t);
                            dev[count].cli_BytesSent = bytesSent;
                        }
                        else if(strstr(propName, ".X_COMCAST-COM_BytesReceived") != NULL)
                        {
                            uint32_t bytesReceived = rbusValue_GetUInt32(paramValue_t);
                            dev[count].cli_BytesReceived = bytesReceived;
                        }
                        else if(strstr(propName, ".X_COMCAST-COM_RSSI") != NULL)
                        {
                            int rssi = rbusValue_GetInt32(paramValue_t);
                            dev[count].cli_RSSI = rssi;
                        }
                        else if(strstr(propName, ".X_COMCAST-COM_MinRSSI") != NULL)
                        {
                            int minRssi = rbusValue_GetInt32(paramValue_t);
                            dev[count].cli_MinRSSI = minRssi;
                        }
                        else if(strstr(propName, ".X_COMCAST-COM_MaxRSSI") != NULL)
                        {
                            int maxRssi = rbusValue_GetInt32(paramValue_t);
                            dev[count].cli_MaxRSSI = maxRssi;
                        }
                        else if(strstr(propName, ".X_COMCAST-COM_Disassociations") != NULL)
                        {
                            uint32_t disassociate = rbusValue_GetUInt32(paramValue_t);
                            dev[count].cli_Disassociations = disassociate;
                        }
                        else if(strstr(propName, ".X_COMCAST-COM_AuthenticationFailures") != NULL)
                        {
                            uint32_t authFail = rbusValue_GetUInt32(paramValue_t);
                            dev[count].cli_AuthenticationFailures = authFail;
                        }
                    }
                }
                next = rbusProperty_GetNext(next);
            }
            rbusProperty_Release(props);
        }
    }
    return 0;
}

int rbus_wifi_getRadioTrafficStats2(int radioIndex, wifi_radioTrafficStats2_t *output_struct)
{
    char path[128] = {'\0'};
    int rc, resCount = 0;
    rbusProperty_t props = NULL;
    rbusValue_t paramValue_t = NULL;

    if(!rbusInitializedCheck())
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s: rbus_open failed\n", __FUNCTION__));
        return 1;
    }

    snprintf(path, sizeof(path), "Device.WiFi.Radio.%d.Stats.", radioIndex);

    const char * wildCardPath[1];
    wildCardPath[0] = path;

    rc = rbus_getExt(rbus_handle, 1, wildCardPath, &resCount, &props);

    if(rc != RBUS_ERROR_SUCCESS)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s: rbus_getExt failed for [%s] with error [%d]\n", __FUNCTION__, path, rc));
        rbusProperty_Release(props);
        return 1;
    }

    if(props != NULL)
    {
        rbusProperty_t next = props;
        while(next != NULL)
        {
            paramValue_t = rbusProperty_GetValue(next);
            if(paramValue_t != NULL)
            {
                char * propName =(char *)rbusProperty_GetName(next);
                if(propName != NULL)
                {
                    if(strstr(propName, ".BytesSent") != NULL)
                    {
                        uint32_t  bytesSent = rbusValue_GetUInt32(paramValue_t);
                        output_struct->radio_BytesSent = bytesSent;
                    }
                    else if(strstr(propName, ".BytesReceived") != NULL)
                    {
                        uint32_t  bytesReceived = rbusValue_GetUInt32(paramValue_t);
                        output_struct->radio_BytesReceived = bytesReceived;
                    }
                    else if(strstr(propName, ".PacketsSent") != NULL)
                    {
                        uint32_t  packetsSent = rbusValue_GetUInt32(paramValue_t);
                        output_struct->radio_PacketsSent = packetsSent;
                    }
                    else if(strstr(propName, ".PacketsReceived") != NULL)
                    {
                        uint32_t  packetsReceived = rbusValue_GetUInt32(paramValue_t);
                        output_struct->radio_PacketsReceived = packetsReceived;
                    }
                    else if(strstr(propName, ".ErrorsSent") != NULL)
                    {
                        uint32_t  errorsSent = rbusValue_GetUInt32(paramValue_t);
                        output_struct->radio_ErrorsSent = errorsSent;
                    }
                    else if(strstr(propName, ".ErrorsReceived") != NULL)
                    {
                        uint32_t  errorsReceived = rbusValue_GetUInt32(paramValue_t);
                        output_struct->radio_ErrorsReceived = errorsReceived;
                    }
                    else if(strstr(propName, ".DiscardPacketsSent") != NULL)
                    {
                        uint32_t  discardPacketsSent = rbusValue_GetUInt32(paramValue_t);
                        output_struct->radio_DiscardPacketsSent = discardPacketsSent;
                    }
                    else if(strstr(propName, ".DiscardPacketsReceived") != NULL)
                    {
                        uint32_t  discardPacketsReceived = rbusValue_GetUInt32(paramValue_t);
                        output_struct->radio_DiscardPacketsReceived = discardPacketsReceived;
                    }
                    else if(strstr(propName, ".PLCPErrorCount") != NULL)
                    {
                         uint32_t  plcpErrorCount = rbusValue_GetUInt32(paramValue_t);
                         output_struct->radio_PLCPErrorCount = plcpErrorCount;
                    }
                    else if(strstr(propName, ".FCSErrorCount") != NULL)
                    {
                        uint32_t  fcsErrorCount = rbusValue_GetUInt32(paramValue_t);
                        output_struct->radio_FCSErrorCount = fcsErrorCount;
                    }
                    else if(strstr(propName, ".InvalidMACCount") != NULL)
                    {
                        uint32_t  invalidMACCount = rbusValue_GetUInt32(paramValue_t);
                        output_struct->radio_InvalidMACCount = invalidMACCount;
                    }
                    else if(strstr(propName, ".PacketsOtherReceived") != NULL)
                    {
                        uint32_t  packetsOtherReceived = rbusValue_GetUInt32(paramValue_t);
                        output_struct->radio_PacketsOtherReceived = packetsOtherReceived;
                    }
                    else if(strstr(propName, ".X_COMCAST-COM_NoiseFloor") != NULL)
                    {
                        int noiseFloor = rbusValue_GetInt32(paramValue_t);
                        output_struct->radio_NoiseFloor = noiseFloor;
                    }
                    else if(strstr(propName, ".X_COMCAST-COM_ChannelUtilization") != NULL)
                    {
                        uint32_t  channelUtilization = rbusValue_GetUInt32(paramValue_t);
                        output_struct->radio_ChannelUtilization = channelUtilization;
                    }
                    else if(strstr(propName, ".X_COMCAST-COM_ActivityFactor") != NULL)
                    {
                        int activityFactor = rbusValue_GetInt32(paramValue_t);
                        output_struct->radio_ActivityFactor = activityFactor;
                    }
                    else if(strstr(propName, ".X_COMCAST-COM_CarrierSenseThreshold_Exceeded") != NULL)
                    {
                        int carrierSenseThreshold_Exceeded = rbusValue_GetInt32(paramValue_t);
                        output_struct->radio_CarrierSenseThreshold_Exceeded = carrierSenseThreshold_Exceeded;
                    }
                    else if(strstr(propName, ".X_COMCAST-COM_RetransmissionMetric") != NULL)
                    {
                        int retransmissionMetric = rbusValue_GetInt32(paramValue_t);
                        output_struct->radio_RetransmissionMetirc = retransmissionMetric;
                    }
                    else if(strstr(propName, ".X_COMCAST-COM_MaximumNoiseFloorOnChannel") != NULL)
                    {
                        int maximumNoiseFloorOnChannel = rbusValue_GetInt32(paramValue_t);
                        output_struct->radio_MaximumNoiseFloorOnChannel = maximumNoiseFloorOnChannel;
                    }
                    else if(strstr(propName, ".X_COMCAST-COM_MinimumNoiseFloorOnChannel") != NULL)
                    {
                        int minimumNoiseFloorOnChannel = rbusValue_GetInt32(paramValue_t);
                        output_struct->radio_MinimumNoiseFloorOnChannel = minimumNoiseFloorOnChannel;
                    }
                    else if(strstr(propName, ".X_COMCAST-COM_MedianNoiseFloorOnChannel") != NULL)
                    {
                        int medianNoiseFloorOnChannel = rbusValue_GetInt32(paramValue_t);
                        output_struct->radio_MedianNoiseFloorOnChannel = medianNoiseFloorOnChannel;
                    }
                    else if(strstr(propName, ".X_COMCAST-COM_StatisticsStartTime") != NULL)
                    {
                        uint32_t  statisticsStartTime = rbusValue_GetUInt32(paramValue_t);
                        output_struct->radio_StatisticsStartTime = statisticsStartTime;
                    }
                }
            }
            next = rbusProperty_GetNext(next);
        }
        rbusProperty_Release(props);
    }
    return 0;
}

int rbus_wifi_getNeighboringWiFiDiagnosticResult2(bool *executed, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *array_size)
{
    int rc = 0;
    bool isCommit = true;
    int sessionId = 0;
    rbusError_t ret = RBUS_ERROR_BUS_ERROR;
    rbusProperty_t last = NULL, next = NULL;
    rbusValue_t setVal[2];

    if(!rbusInitializedCheck())
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s: rbus_open failed\n", __FUNCTION__));
        return 1;
    }

    rbusSetOptions_t opts = {isCommit,sessionId};

    rbusValue_Init(&setVal[0]);
    rbusValue_SetFromString(setVal[0], RBUS_BOOLEAN, "true");

    rbusValue_Init(&setVal[1]);
    rbusValue_SetFromString(setVal[1], RBUS_STRING, "Requested");

    rbusProperty_Init(&next, "Device.WiFi.NeighboringWiFiDiagnostic.Enable", setVal[0]);
    rbusProperty_Init(&last, "Device.WiFi.NeighboringWiFiDiagnostic.DiagnosticsState", setVal[1]);
    rbusProperty_SetNext(next, last);

    ret = rbus_setMulti(rbus_handle, 2, next, &opts);
    if(ret != RBUS_ERROR_SUCCESS)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s: rbus_set failed for [%s] with error [%d]\n", __FUNCTION__, "NeighboringWiFiDiagnostic", rc));
        if(setVal != NULL)
        {
            rbusValue_Release(setVal[0]);
            rbusValue_Release(setVal[1]);
        }
        return 1;
    }
    CcspHarvesterConsoleTrace(("RDK_LOG_INFO, Harvester %s: rbus_set to enable neighboring wifi diagnostics results is success %d\n", __FUNCTION__, ret));

    rbusValue_Release(setVal[0]);
    rbusValue_Release(setVal[1]);
    rbusProperty_Release(next);

    // Wait until the Device.WiFi.NeighboringWiFiDiagnostic.DiagnosticsState is "Completed"
    char state[128] = {0};
    char *stateParam = "Device.WiFi.NeighboringWiFiDiagnostic.DiagnosticsState";
    int cnt=0;
    while(ret == RBUS_ERROR_SUCCESS)
    {
        ret = rbus_getStringValue(state, stateParam);
        if(strncmp(state, "Completed", 9) == 0)
            break;
        else
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s: rbus get of %s is %s, ret %d\n", __FUNCTION__, stateParam, state, ret));
        cnt++;
        if(cnt == 13) // Reached max wait of 12*5 = 60s, hence breakout of loop
            break;
        sleep(5);
    }

    rbusValue_t neighWiFiResultVal;
    char *path = "Device.WiFi.NeighboringWiFiDiagnostic.ResultNumberOfEntries";
    char wildcardPath[128] = {'\0'};
    char *params[1];
    rbusProperty_t props = NULL;
    int count = 0, resCount = 0;
    rbusValue_t paramValue_t = NULL;
    rc = rbus_get(rbus_handle, path, &neighWiFiResultVal);

    if(rc != RBUS_ERROR_SUCCESS)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s: rbus_get failed for [%s] with error [%d]\n", __FUNCTION__, path, rc));
        if(neighWiFiResultVal != NULL)
        {
            rbusValue_Release(neighWiFiResultVal);
        }
        return 1;
    }

    *array_size = rbusValue_GetUInt32(neighWiFiResultVal);

    if(*array_size == 0)
    {
        CcspHarvesterTrace(("RDK_LOG_INFO, Harvester %s: neighboring wifi diagnostics results are not available\n", __FUNCTION__));
        return 1;
    }
    CcspHarvesterTrace(("RDK_LOG_INFO, Harvester %s: %d neighboring wifi diagnostics results available\n", __FUNCTION__, *array_size));

    wifi_neighbor_ap2_t *tmp_neighbor_ap_arr = NULL;

    tmp_neighbor_ap_arr = (wifi_neighbor_ap2_t *) calloc(*array_size, sizeof(wifi_neighbor_ap2_t));
    *neighbor_ap_array = tmp_neighbor_ap_arr;

    snprintf(wildcardPath, sizeof(wildcardPath), "Device.WiFi.NeighboringWiFiDiagnostic.Result.");
    params[0] = wildcardPath;

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s: calling rbus get for %s\n", __FUNCTION__, wildcardPath));

    rc = rbus_getExt(rbus_handle, 1, (const char **) params, &resCount, &props);

    if(rc != RBUS_ERROR_SUCCESS)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s: rbus_getExt failed for [%s] with error [%d]\n", __FUNCTION__, wildcardPath, rc));
        rbusProperty_Release(props);
        return 1;
    }
    if(props != NULL)
    {
        rbusProperty_t next = props;

        while(next != NULL)
        {
            paramValue_t = rbusProperty_GetValue(next);

            if(paramValue_t != NULL)
            {
                char * propName = (char *) rbusProperty_GetName(next);

                sscanf(propName, "Device.WiFi.NeighboringWiFiDiagnostic.Result.%d", &count);
		count = count-1;
		if(count<0)
		{
			CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s: the index %d, is less than 0\n", wildcardPath, count));
			return 1;
		}
                CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s: %d results available, iteration %d\n", wildcardPath, resCount, count));
                if(propName != NULL)
                {
                    if(strstr(propName, ".SSID") != NULL)
                    {
                        char * ssid = (char *)rbusValue_GetString(paramValue_t, NULL);
                        if(ssid != NULL)
                        {
                            strcpy_s(tmp_neighbor_ap_arr[count].ap_SSID,64,ssid);
                        }
                        else
                            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s value is NULL\n", propName));
                    }
                    else if(strstr(propName, ".BSSID") != NULL)
                    {
                        char * bssid = (char *)rbusValue_GetString(paramValue_t, NULL);
                        if(bssid != NULL)
                        {
                            strcpy_s(tmp_neighbor_ap_arr[count].ap_BSSID,64,bssid);
                        }
                        else
                            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s value is NULL\n", propName));
                    }
                    else if(strstr(propName, ".Mode") != NULL)
                    {
                        char * mode = (char *)rbusValue_GetString(paramValue_t, NULL);
                        if(mode != NULL)
                        {
                            strcpy_s(tmp_neighbor_ap_arr[count].ap_Mode,64,mode);
                        }
                        else
                            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s value is NULL\n", propName));
                    }
                    else if(strstr(propName, ".Channel") != NULL)
                    {
                        uint32_t channel = rbusValue_GetUInt32(paramValue_t);
                        tmp_neighbor_ap_arr[count].ap_Channel = channel;
                    }
                    else if(strstr(propName, ".SignalStrength") != NULL)
                    {
                        int signalStrength  = rbusValue_GetInt32(paramValue_t);
                        tmp_neighbor_ap_arr[count].ap_SignalStrength = signalStrength;
                    }
                    else if(strstr(propName, ".SecurityModeEnabled") != NULL)
                    {
                        char * securityModeEnabled = (char *)rbusValue_GetString(paramValue_t, NULL);
                        if(securityModeEnabled != NULL)
                        {
                            strcpy_s(tmp_neighbor_ap_arr[count].ap_SecurityModeEnabled,64,securityModeEnabled);
                        }
                        else
                            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s value is NULL\n", propName));
                    }
                    else if(strstr(propName, ".EncryptionMode") != NULL)
                    {
                        char * encryptionMode = (char *)rbusValue_GetString(paramValue_t, NULL);
                        if(encryptionMode != NULL)
                        {
                            strcpy_s(tmp_neighbor_ap_arr[count].ap_EncryptionMode,64,encryptionMode);
                        }
                        else
                            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s value is NULL\n", propName));
                    }
                    else if(strstr(propName, ".OperatingFrequencyBand") != NULL)
                    {
                        char * operatingFrequencyBand = (char *)rbusValue_GetString(paramValue_t, NULL);
                        if(operatingFrequencyBand != NULL)
                        {
                            strcpy_s(tmp_neighbor_ap_arr[count].ap_OperatingFrequencyBand,16, operatingFrequencyBand);
                        }
                        else
                            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s value is NULL\n", propName));
                    }
                    else if(strstr(propName, ".SupportedStandards") != NULL)
                    {
                        char * supportedStandards = (char *)rbusValue_GetString(paramValue_t, NULL);
                        if(supportedStandards != NULL)
                        {
                            strcpy_s(tmp_neighbor_ap_arr[count].ap_SupportedStandards,64,supportedStandards);
                        }
                        else
                            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s value is NULL\n", propName));
                    }
                    else if(strstr(propName, ".OperatingStandards") != NULL)
                    {
                        char * operatingStandards = (char *)rbusValue_GetString(paramValue_t, NULL);
                        if(operatingStandards != NULL)
                        {
                            strcpy_s(tmp_neighbor_ap_arr[count].ap_OperatingStandards,16,operatingStandards);
                        }
                        else
                            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s value is NULL\n", propName));
                    }
                    else if(strstr(propName, ".OperatingChannelBandwidth") != NULL)
                    {
                        char * operatingChannelBandwidth = (char *)rbusValue_GetString(paramValue_t, NULL);
                        if(operatingChannelBandwidth != NULL)
                        {
                            strcpy_s(tmp_neighbor_ap_arr[count].ap_OperatingChannelBandwidth,16, operatingChannelBandwidth);
                        }
                        else
                            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s value is NULL\n", propName));
                    }
                    else if(strstr(propName, ".BeaconPeriod") != NULL)
                    {
                        uint32_t beaconPeriod = rbusValue_GetUInt32(paramValue_t);
                        tmp_neighbor_ap_arr[count].ap_BeaconPeriod = beaconPeriod;
                    }
                    else if(strstr(propName, ".Noise") != NULL)
                    {
                        int noise = rbusValue_GetInt32(paramValue_t);
                        tmp_neighbor_ap_arr[count].ap_Noise = noise;
                    }
                    else if(strstr(propName, ".BasicDataTransferRates") != NULL)
                    {
                        char * basicDataTransferRates = (char *)rbusValue_GetString(paramValue_t, NULL);
                        if(basicDataTransferRates != NULL)
                        {
                            strcpy_s(tmp_neighbor_ap_arr[count].ap_BasicDataTransferRates,256, basicDataTransferRates);
                        }
                        else
                            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s value is NULL\n", propName));
                    }
                    else if(strstr(propName, ".SupportedDataTransferRates") != NULL)
                    {
                        char * supportedDataTransferRates = (char *)rbusValue_GetString(paramValue_t, NULL);
                        if(supportedDataTransferRates != NULL)
                        {
                            strcpy_s(tmp_neighbor_ap_arr[count].ap_SupportedDataTransferRates,256, supportedDataTransferRates);
                        }
                        else
                            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s value is NULL\n", propName));
                    }
                    else if(strstr(propName, ".DTIMPeriod") != NULL)
                    {
                        uint32_t dtimPeriod = rbusValue_GetUInt32(paramValue_t);
                        tmp_neighbor_ap_arr[count].ap_DTIMPeriod = dtimPeriod;
                    }
                    else if(strstr(propName, ".X_COMCAST-COM_ChannelUtilization") != NULL)
                    {
                        uint32_t channelUtilization = rbusValue_GetUInt32(paramValue_t);
                        tmp_neighbor_ap_arr[count].ap_ChannelUtilization = channelUtilization;
                    }
                }
                else
                    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester propName is NULL\n"));
            }
            else
                CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester paramValue_t is NULL\n" ));
            next = rbusProperty_GetNext(next);
        }
        rbusProperty_Release(props);
    }

    // setting the flag to indicate the diagnostic is already run
    *executed = true;
    return 0;
}
// End of File

