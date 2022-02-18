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

#include "ansc_platform.h"
#include "cosa_harvester_dml.h"
#include "cosa_harvester_internal.h"
#include "ssp_global.h"
#include "base64.h"
#include "ccsp_trace.h"
#include "ccsp_psm_helper.h"

/*Added for rdkb-4343*/
#include "ccsp_harvesterLog_wrapper.h"

#include "harvester_associated_devices.h"
#include "harvester_neighboring_ap.h"
#include "harvester_radio_traffic.h"
#include "harvester_neighboring_ap_ondemand.h"
#include "safec_lib_common.h"



extern ANSC_HANDLE bus_handle;
extern char g_Subsystem[32];
extern COSA_DATAMODEL_HARVESTER* g_pHarvester;

static char *InterfaceDevicesWifiEnabled              = "eRT.com.cisco.spvtg.ccsp.harvester.InterfaceDevicesWifiEnabled";
static char *InterfaceDevicesWifiPollingPeriod        = "eRT.com.cisco.spvtg.ccsp.harvester.InterfaceDevicesWifiPollingPeriod";
static char *InterfaceDevicesWifiReportingPeriod      = "eRT.com.cisco.spvtg.ccsp.harvester.InterfaceDevicesWifiReportingPeriod";
static char *InterfaceDevicesWifiDefaultPollingPeriod        = "eRT.com.cisco.spvtg.ccsp.harvester.InterfaceDevicesWifiDefaultPollingPeriod";
static char *InterfaceDevicesWifiDefaultReportingPeriod      = "eRT.com.cisco.spvtg.ccsp.harvester.InterfaceDevicesWifiDefaultReportingPeriod";

static char *RadioInterfaceStatisticsEnabled              = "eRT.com.cisco.spvtg.ccsp.harvester.RadioInterfaceStatisticsEnabled";
static char *RadioInterfaceStatisticsPollingPeriod        = "eRT.com.cisco.spvtg.ccsp.harvester.RadioInterfaceStatisticsPollingPeriod";
static char *RadioInterfaceStatisticsReportingPeriod      = "eRT.com.cisco.spvtg.ccsp.harvester.RadioInterfaceStatisticsReportingPeriod";
static char *RadioInterfaceStatisticsDefaultPollingPeriod        = "eRT.com.cisco.spvtg.ccsp.harvester.RadioInterfaceStatisticsDefaultPollingPeriod";
static char *RadioInterfaceStatisticsDefaultReportingPeriod      = "eRT.com.cisco.spvtg.ccsp.harvester.RadioInterfaceStatisticsDefaultReportingPeriod";

static char *NeighboringAPEnabled              = "eRT.com.cisco.spvtg.ccsp.harvester.NeighboringAPEnabled";
static char *NeighboringAPPollingPeriod        = "eRT.com.cisco.spvtg.ccsp.harvester.NeighboringAPPollingPeriod";
static char *NeighboringAPReportingPeriod      = "eRT.com.cisco.spvtg.ccsp.harvester.NeighboringAPReportingPeriod";
static char *NeighboringAPDefaultPollingPeriod        = "eRT.com.cisco.spvtg.ccsp.harvester.NeighboringAPDefaultPollingPeriod";
static char *NeighboringAPDefaultReportingPeriod      = "eRT.com.cisco.spvtg.ccsp.harvester.NeighboringAPDefaultReportingPeriod";

//RDKB-9258 : save periods after TTL expiry to NVRAM
static pthread_mutex_t g_idwNvramMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_risNvramMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_napNvramMutex = PTHREAD_MUTEX_INITIALIZER;

extern char* GetNeighborAPAvroBuf();
extern int GetNeighborAPAvroBufSize();

extern char* GetIDWSchemaBuffer();
extern int GetIDWSchemaBufferSize();
extern char* GetIDWSchemaIDBuffer();
extern int GetIDWSchemaIDBufferSize();

extern char* GetNAPSchemaBuffer();
extern int GetNAPSchemaBufferSize();
extern char* GetNAPSchemaIDBuffer();
extern int GetNAPSchemaIDBufferSize();

extern char* GetRISSchemaBuffer();
extern int GetRISSchemaBufferSize();
extern char* GetRISSchemaIDBuffer();
extern int GetRISSchemaIDBufferSize();
INT wifi_context_init();


ANSC_STATUS GetNVRamULONGConfiguration(char* setting, ULONG* value)
{
    char *strValue = NULL;
    int retPsmGet = CCSP_SUCCESS;

    retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, setting, NULL, &strValue);
    if (retPsmGet == CCSP_SUCCESS) {
        *value = _ansc_atoi(strValue);
        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(strValue);
    }
    return retPsmGet;
}

ANSC_STATUS SetNVRamULONGConfiguration(char* setting, ULONG value)
{
    int retPsmSet = CCSP_SUCCESS;
    char psmValue[32] = {};
    ULONG psm_value = 0;
    errno_t rc =-1;

    retPsmSet = GetNVRamULONGConfiguration(setting,&psm_value);

    if ((retPsmSet == CCSP_SUCCESS) && (psm_value == value))
    {
      CcspHarvesterConsoleTrace(("%s PSM value is same for setting [%s] Value [%lu]\n",__FUNCTION__,setting, value));
      return retPsmSet;
    }

    rc = sprintf_s(psmValue,sizeof(psmValue),"%lu",value);
    if(rc < EOK)
    {
      ERR_CHK(rc);
      return CCSP_FAILURE;
    }
    retPsmSet = PSM_Set_Record_Value2(bus_handle,g_Subsystem, setting, ccsp_string, psmValue);
    if (retPsmSet != CCSP_SUCCESS) 
        {
        CcspHarvesterConsoleTrace(("RDK_LOG_ERROR, Harvester %s : PSM_Set_Record_Value2 Failed with Setting[%s] Value[%s] \n", __FUNCTION__ , setting, psmValue ));            
        }
    else
        {
        CcspHarvesterConsoleTrace(("RDK_LOG_ERROR, Harvester %s : PSM_Set_Record_Value2 SUCCESS with Setting[%s] Value[%s] \n", __FUNCTION__ , setting, psmValue ));            
        }
    return retPsmSet;
}

// Persisting IDW Polling period
ANSC_STATUS
SetIDWPollingPeriodInNVRAM(ULONG pPollingVal)
{
    ANSC_STATUS     returnStatus = ANSC_STATUS_SUCCESS;

    //Acquire mutex
    pthread_mutex_lock(&g_idwNvramMutex);

    g_pHarvester->uIDWPollingPeriod = pPollingVal;
    returnStatus = SetNVRamULONGConfiguration(InterfaceDevicesWifiPollingPeriod, pPollingVal);
    g_pHarvester->bIDWPollingPeriodChanged = false;

    //Release mutex
    pthread_mutex_unlock(&g_idwNvramMutex);

    return returnStatus;
}

// Persisting IDW Reporting period
ANSC_STATUS
SetIDWReportingPeriodInNVRAM(ULONG pReportingVal)
{
    ANSC_STATUS     returnStatus = ANSC_STATUS_SUCCESS;

    //Acquire mutex
    pthread_mutex_lock(&g_idwNvramMutex);

    g_pHarvester->uIDWReportingPeriod = pReportingVal;
    returnStatus =  SetNVRamULONGConfiguration(InterfaceDevicesWifiReportingPeriod, pReportingVal);
    g_pHarvester->bIDWReportingPeriodChanged = false;

    //Release mutex
    pthread_mutex_unlock(&g_idwNvramMutex);

    return returnStatus;
}

// Persisting RIS Polling period
ANSC_STATUS
SetRISPollingPeriodInNVRAM(ULONG pPollingVal)
{
    ANSC_STATUS     returnStatus = ANSC_STATUS_SUCCESS;

    //Acquire mutex
    pthread_mutex_lock(&g_risNvramMutex);

    g_pHarvester->uRISPollingPeriod = pPollingVal;
    returnStatus = SetNVRamULONGConfiguration(RadioInterfaceStatisticsPollingPeriod, pPollingVal);
    g_pHarvester->bRISPollingPeriodChanged = false;

    //Release mutex
    pthread_mutex_unlock(&g_risNvramMutex);

    return returnStatus;
}

// Persisting RIS Reporting period
ANSC_STATUS
SetRISReportingPeriodInNVRAM(ULONG pReportingVal)
{
    ANSC_STATUS     returnStatus = ANSC_STATUS_SUCCESS;

    //Acquire mutex
    pthread_mutex_lock(&g_risNvramMutex);

    g_pHarvester->uRISReportingPeriod = pReportingVal;
    returnStatus =  SetNVRamULONGConfiguration(RadioInterfaceStatisticsReportingPeriod, pReportingVal);
    g_pHarvester->bRISReportingPeriodChanged = false;

    //Release mutex
    pthread_mutex_unlock(&g_risNvramMutex);

    return returnStatus;
}

// Persisting NAP Polling period
ANSC_STATUS
SetNAPPollingPeriodInNVRAM(ULONG pPollingVal)
{
    ANSC_STATUS     returnStatus = ANSC_STATUS_SUCCESS;

    //Acquire mutex
    pthread_mutex_lock(&g_napNvramMutex);

    g_pHarvester->uNAPPollingPeriod = pPollingVal;
    returnStatus = SetNVRamULONGConfiguration(NeighboringAPPollingPeriod, pPollingVal);
    g_pHarvester->bNAPPollingPeriodChanged = false;

    //Release mutex
    pthread_mutex_unlock(&g_napNvramMutex);

    return returnStatus;
}

// Persisting NAP Reporting period
ANSC_STATUS
SetNAPReportingPeriodInNVRAM(ULONG pReportingVal)
{
    ANSC_STATUS     returnStatus = ANSC_STATUS_SUCCESS;

    //Acquire mutex
    pthread_mutex_lock(&g_napNvramMutex);

    g_pHarvester->uNAPReportingPeriod = pReportingVal;
    returnStatus = SetNVRamULONGConfiguration(NeighboringAPReportingPeriod, pReportingVal);
    g_pHarvester->bNAPReportingPeriodChanged = false;

    //Release mutex
    pthread_mutex_unlock(&g_napNvramMutex);

    return returnStatus;
}

ANSC_STATUS
CosaDmlHarvesterInit
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus        = ANSC_STATUS_SUCCESS;
    int retPsmGet = CCSP_SUCCESS;
    ULONG psmValue = 0;

    retPsmGet = GetNVRamULONGConfiguration(InterfaceDevicesWifiEnabled, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pHarvester->bIDWEnabled = psmValue;
        SetIDWHarvestingStatus(g_pHarvester->bIDWEnabled);
    }

    retPsmGet = GetNVRamULONGConfiguration(InterfaceDevicesWifiDefaultPollingPeriod, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pHarvester->uIDWDefaultPollingPeriod = psmValue;
        SetIDWPollingPeriodDefault(g_pHarvester->uIDWDefaultPollingPeriod);
    }

    retPsmGet = GetNVRamULONGConfiguration(InterfaceDevicesWifiDefaultReportingPeriod, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pHarvester->uIDWDefaultReportingPeriod = psmValue;
        SetIDWReportingPeriodDefault(g_pHarvester->uIDWDefaultReportingPeriod);
    } 

    retPsmGet = GetNVRamULONGConfiguration(InterfaceDevicesWifiPollingPeriod, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pHarvester->uIDWPollingPeriod = psmValue;
        SetIDWPollingPeriod(g_pHarvester->uIDWPollingPeriod);
    }

    retPsmGet = GetNVRamULONGConfiguration(InterfaceDevicesWifiReportingPeriod, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pHarvester->uIDWReportingPeriod = psmValue;
        SetIDWReportingPeriod(g_pHarvester->uIDWReportingPeriod);
    } 
     
    retPsmGet = GetNVRamULONGConfiguration(RadioInterfaceStatisticsEnabled, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pHarvester->bRISEnabled = psmValue;
        SetRISHarvestingStatus(g_pHarvester->bRISEnabled);
    }

    retPsmGet = GetNVRamULONGConfiguration(RadioInterfaceStatisticsDefaultPollingPeriod, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pHarvester->uRISDefaultPollingPeriod = psmValue;
        SetRISPollingPeriodDefault(g_pHarvester->uRISDefaultPollingPeriod);
    }

    retPsmGet = GetNVRamULONGConfiguration(RadioInterfaceStatisticsDefaultReportingPeriod, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pHarvester->uRISDefaultReportingPeriod = psmValue;
        SetRISReportingPeriodDefault(g_pHarvester->uRISDefaultReportingPeriod);
    } 

    retPsmGet = GetNVRamULONGConfiguration(RadioInterfaceStatisticsPollingPeriod, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pHarvester->uRISPollingPeriod = psmValue;
        SetRISPollingPeriod(g_pHarvester->uRISPollingPeriod);
    }

    retPsmGet = GetNVRamULONGConfiguration(RadioInterfaceStatisticsReportingPeriod, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pHarvester->uRISReportingPeriod = psmValue;
        SetRISReportingPeriod(g_pHarvester->uRISReportingPeriod);
    } 

    retPsmGet = GetNVRamULONGConfiguration(NeighboringAPEnabled, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pHarvester->bNAPEnabled = psmValue;
        SetNAPHarvestingStatus(g_pHarvester->bNAPEnabled);
    }

    retPsmGet = GetNVRamULONGConfiguration(NeighboringAPDefaultPollingPeriod, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pHarvester->uNAPDefaultPollingPeriod = psmValue;
        SetNAPPollingPeriodDefault(g_pHarvester->uNAPDefaultPollingPeriod);
    }

    retPsmGet = GetNVRamULONGConfiguration(NeighboringAPDefaultReportingPeriod, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pHarvester->uNAPDefaultReportingPeriod = psmValue;
        SetNAPReportingPeriodDefault(g_pHarvester->uNAPDefaultReportingPeriod);
    }     

    retPsmGet = GetNVRamULONGConfiguration(NeighboringAPPollingPeriod, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pHarvester->uNAPPollingPeriod = psmValue;
        SetNAPPollingPeriod(g_pHarvester->uNAPPollingPeriod);
    }

    retPsmGet = GetNVRamULONGConfiguration(NeighboringAPReportingPeriod, &psmValue);
    if (retPsmGet == CCSP_SUCCESS) {
        g_pHarvester->uNAPReportingPeriod = psmValue;
        SetNAPReportingPeriod(g_pHarvester->uNAPReportingPeriod);
    }     

    return returnStatus;
}

BOOL
InterfaceDevicesWifi_GetParamBoolValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    BOOL*                       pBool
)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));

    errno_t rc =-1;
    int ind =-1;

    if(ParamName == NULL)
           return FALSE;

    /* check the parameter name and return the corresponding value */
    rc = strcmp_s("Enabled", strlen("Enabled"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        /* collect value */
        *pBool    =  GetIDWHarvestingStatus();
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%d] \n", __FUNCTION__ , ParamName, *pBool ));
        return TRUE;
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
    return FALSE;
}

BOOL
InterfaceDevicesWifi_SetParamBoolValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    BOOL                        bValue
)
{
   CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t rc =-1;
    int ind =-1;

    if(ParamName == NULL)
        return FALSE;

    /* check the parameter name and set the corresponding value */
    rc = strcmp_s("Enabled", strlen("Enabled"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        g_pHarvester->bIDWEnabledChanged = true;
        g_pHarvester->bIDWEnabled = bValue;
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%d] \n", __FUNCTION__ , ParamName, bValue ));
        CcspTraceInfo(("RDKB_HARVESTER_VALUE_CHANGED - WiFiInterfaceDevice Report %s\n", (bValue) ?  "Enabled" : "Disabled" ));
        return TRUE;
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
    return FALSE;
}


BOOL
InterfaceDevicesWifi_Default_GetParamUlongValue
    (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
    )
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t     rc =  -1;
    int ind = -1;

    if(ParamName == NULL)
         return FALSE;

    rc = strcmp_s("PollingPeriod", strlen("PollingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        *puLong =  GetIDWPollingPeriodDefault();
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    rc =  strcmp_s( "ReportingPeriod",strlen("ReportingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        *puLong =  GetIDWReportingPeriodDefault();
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    rc = strcmp_s("OverrideTTL",strlen("OverrideTTL"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        *puLong =  GetIDWOverrideTTLDefault();
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

    return FALSE;
}

BOOL
InterfaceDevicesWifi_GetParamUlongValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    ULONG*                      puLong
)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t     rc =  -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("PollingPeriod", strlen("PollingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        *puLong =  GetIDWPollingPeriod();
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    rc =  strcmp_s( "ReportingPeriod",strlen("ReportingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        *puLong =  GetIDWReportingPeriod();
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

    return FALSE;
}

BOOL
InterfaceDevicesWifi_SetParamUlongValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    ULONG                       uValue
)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t     rc =  -1;
    int ind = -1;

    if(ParamName == NULL)
       return FALSE;

    rc = strcmp_s("PollingPeriod", strlen("PollingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        g_pHarvester->bIDWPollingPeriodChanged = true;
        g_pHarvester->uIDWPollingPeriod = uValue;
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, uValue ));
        return TRUE;
    }

    rc =  strcmp_s( "ReportingPeriod",strlen("ReportingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        g_pHarvester->bIDWReportingPeriodChanged = true;
        g_pHarvester->uIDWReportingPeriod = uValue;
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, uValue ));
        return TRUE;
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
    return FALSE;
}

BOOL
InterfaceDevicesWifi_Default_SetParamUlongValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    ULONG                       uValue
)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t     rc =  -1;
    int ind = -1;

    if(ParamName == NULL)
       return FALSE;

    rc = strcmp_s("PollingPeriod", strlen("PollingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        g_pHarvester->bIDWDefaultPollingPeriodChanged = true;
        g_pHarvester->uIDWDefaultPollingPeriod = uValue;
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, uValue ));
        return TRUE;
    }

    rc =  strcmp_s( "ReportingPeriod",strlen("ReportingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        g_pHarvester->bIDWDefaultReportingPeriodChanged = true;
        g_pHarvester->uIDWDefaultReportingPeriod = uValue;
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, uValue ));
        return TRUE;
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
    return FALSE;
}

BOOL
InterfaceDevicesWifi_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t     rc =  -1;
    int ind = -1;

    if(ParamName == NULL)
       return FALSE;

    rc = strcmp_s("Schema", strlen("Schema"),ParamName,&ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        /* collect value */
        int bufsize = GetIDWSchemaBufferSize();
        if(!bufsize)
        {
            char result[1024] = "Schema Buffer is empty";
            rc = strcpy_s(pValue,*pUlSize, (char*)&result);
            if(rc != EOK)
            {
              ERR_CHK(rc);
            }
            return FALSE;
        }
        else
    {
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Buffer Size [%d] InputSize [%lu]\n", bufsize, *pUlSize));
        if (bufsize < *pUlSize)
        {
            /*
             * LIMITATION
             * Following AnscCopyString() can't modified to safec strcpy_s() api
             * Because, safec has the limitation of copying only 4k ( RSIZE_MAX ) to destination pointer
             * And here, we have source pointer size more than 4k, i.e simetimes 190k also
            */
            AnscCopyString(pValue, GetIDWSchemaBuffer());
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, pValue Buffer Size [%d] \n", (int)strlen(pValue)));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
            return FALSE;
        }
        else
        {
            *pUlSize = bufsize + 1;
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
            return TRUE;
        }
    }
    }

    rc = strcmp_s("SchemaID", strlen("SchemaID"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        /* collect value */
        int bufsize = GetIDWSchemaIDBufferSize();
        if(!bufsize)
        {
            char result[1024] = "SchemaID Buffer is empty";
            rc =  strcpy_s(pValue,*pUlSize, (char*)&result);
            if(rc != EOK)
            {
               ERR_CHK(rc);
            }
            return FALSE;
        }
        else
        {

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Buffer Size [%d] InputSize [%lu]\n", bufsize, *pUlSize));
        if (bufsize < *pUlSize)
        {
            rc = strcpy_s(pValue,*pUlSize, GetIDWSchemaIDBuffer());
            if(rc != EOK)
            {
              ERR_CHK(rc);
              return FALSE;
            }
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, pValue Buffer Size [%d] \n", (int)strlen(pValue)));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
            return FALSE;
        }
        else
        {
            *pUlSize = bufsize + 1;
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
            return TRUE;
        }
    }
    }

    AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

    return FALSE;
}



/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        InterfaceDevicesWifi_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
InterfaceDevicesWifi_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t rc = -1;

    if(g_pHarvester->bIDWDefaultPollingPeriodChanged)
    {
        BOOL validated = ValidateIDWPeriod(g_pHarvester->uIDWDefaultPollingPeriod);    
        if(!validated)
        {
           CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : Default PollingPeriod Validation Failed : [%lu] Value not Allowed \n", __FUNCTION__ , g_pHarvester->uIDWDefaultPollingPeriod));
            rc =  strcpy_s(pReturnParamName,*puLength, "PollingPeriod");
            if(rc != EOK)
            {
              ERR_CHK(rc);
              return FALSE;
            }
            *puLength = AnscSizeOfString("PollingPeriod");
            return FALSE;
        }
    }

    if(g_pHarvester->bIDWDefaultReportingPeriodChanged)
    {
        BOOL validated = ValidateIDWPeriod(g_pHarvester->uIDWDefaultReportingPeriod);    
        if(!validated)
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : Default ReportingPeriod Validation Failed : [%lu] Value not Allowed \n", __FUNCTION__ , g_pHarvester->uIDWDefaultReportingPeriod));
            rc =  strcpy_s(pReturnParamName,*puLength, "ReportingPeriod");
            if(rc != EOK)
            {
               ERR_CHK(rc);
               return FALSE;
            }
            *puLength = AnscSizeOfString("ReportingPeriod");
            return FALSE;
        }
    }

    if(g_pHarvester->bIDWPollingPeriodChanged)
    {
        BOOL validated = ValidateIDWPeriod(g_pHarvester->uIDWPollingPeriod);    
        if(!validated)
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : PollingPeriod Validation Failed : [%lu] Value not Allowed \n", __FUNCTION__ , g_pHarvester->uIDWPollingPeriod));
            rc =  strcpy_s(pReturnParamName,*puLength, "PollingPeriod");
            if(rc != EOK)
            {
              ERR_CHK(rc);
              return FALSE;
            }
            *puLength = AnscSizeOfString("PollingPeriod");
            return FALSE;
        }
        if(GetIDWHarvestingStatus() && g_pHarvester->uIDWPollingPeriod > GetIDWPollingPeriod())
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : PollingPeriod Validation Failed : New Polling Period [%lu] > Current Polling Period [%lu] \n", __FUNCTION__ , g_pHarvester->uIDWPollingPeriod, GetIDWPollingPeriod() ));
            rc =  strcpy_s(pReturnParamName,*puLength, "PollingPeriod");
            if(rc != EOK)
            {
              ERR_CHK(rc);
              return FALSE;
            }
            *puLength = AnscSizeOfString("PollingPeriod");
            return FALSE;           
        }

        ULONG period = (g_pHarvester->bIDWReportingPeriodChanged == TRUE) ? g_pHarvester->uIDWReportingPeriod : GetIDWReportingPeriod();
        if(g_pHarvester->uIDWPollingPeriod > period)
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : PollingPeriod Validation Failed : New Polling Period [%lu] > Current Reporting Period [%lu] \n", __FUNCTION__ , g_pHarvester->uIDWPollingPeriod, period ));
            rc =  strcpy_s(pReturnParamName,*puLength, "PollingPeriod");
            if(rc != EOK)
            {
               ERR_CHK(rc);
               return FALSE;
            }
            *puLength = AnscSizeOfString("PollingPeriod");
            return FALSE;           
        }
    }

    if(g_pHarvester->bIDWReportingPeriodChanged)
    {
        BOOL validated = ValidateIDWPeriod(g_pHarvester->uIDWReportingPeriod);    
        if(!validated)
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : ReportingPeriod Validation Failed : [%lu] Value not Allowed \n", __FUNCTION__ , g_pHarvester->uIDWReportingPeriod));
            rc =  strcpy_s(pReturnParamName,*puLength, "ReportingPeriod");
            if(rc != EOK)
            {
              ERR_CHK(rc);
              return FALSE;
            }
            *puLength = AnscSizeOfString("ReportingPeriod");
            return FALSE;
        }
        ULONG period = (g_pHarvester->bIDWPollingPeriodChanged == TRUE) ? g_pHarvester->uIDWPollingPeriod : GetIDWPollingPeriod();
        if(g_pHarvester->uIDWReportingPeriod < period)
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : ReportingPeriod Validation Failed : New Reporting Period [%lu] < Current Polling Period [%lu] \n", __FUNCTION__ , g_pHarvester->uIDWReportingPeriod, period ));
            rc =  strcpy_s(pReturnParamName,*puLength, "ReportingPeriod");
            if(rc != EOK)
            {
               ERR_CHK(rc);
               return FALSE;
            }
            *puLength = AnscSizeOfString("ReportingPeriod");
            return FALSE;           
        }
        if(GetIDWHarvestingStatus() && g_pHarvester->uIDWReportingPeriod > GetIDWReportingPeriod())
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : ReportingPeriod Validation Failed : New Reporting Period [%lu] > Current Reporting Period [%lu] \n", __FUNCTION__ , g_pHarvester->uIDWReportingPeriod, GetIDWReportingPeriod() ));
            rc =  strcpy_s(pReturnParamName,*puLength, "ReportingPeriod");
            if(rc != EOK)
            {
              ERR_CHK(rc);
              return FALSE;
            }
            *puLength = AnscSizeOfString("ReportingPeriod");
            return FALSE;           
        }
    }

     CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        InterfaceDevicesWifi_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
InterfaceDevicesWifi_Commit
(
    ANSC_HANDLE                 hInsContext
)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    ULONG psmValue = 0;
    /* Network Device Parameters*/

    if(g_pHarvester->bIDWEnabledChanged)
    {
    SetIDWHarvestingStatus(g_pHarvester->bIDWEnabled);
    psmValue = g_pHarvester->bIDWEnabled;
    SetNVRamULONGConfiguration(InterfaceDevicesWifiEnabled, psmValue);
    g_pHarvester->bIDWEnabledChanged = false;
    }

    if(g_pHarvester->bIDWDefaultPollingPeriodChanged)
    {
    SetIDWPollingPeriodDefault(g_pHarvester->uIDWDefaultPollingPeriod);
    psmValue = g_pHarvester->uIDWDefaultPollingPeriod;
    SetNVRamULONGConfiguration(InterfaceDevicesWifiDefaultPollingPeriod, psmValue);
    g_pHarvester->bIDWDefaultPollingPeriodChanged = false;
    }

    if(g_pHarvester->bIDWDefaultReportingPeriodChanged)
    {
    SetIDWReportingPeriodDefault(g_pHarvester->uIDWDefaultReportingPeriod);
    psmValue = g_pHarvester->uIDWDefaultReportingPeriod;
    SetNVRamULONGConfiguration(InterfaceDevicesWifiDefaultReportingPeriod, psmValue);
    g_pHarvester->bIDWDefaultReportingPeriodChanged = false;
    }

    if(g_pHarvester->bIDWPollingPeriodChanged)
    {
    psmValue = g_pHarvester->uIDWPollingPeriod;
    SetIDWPollingPeriod( psmValue );
    SetIDWOverrideTTL(GetIDWOverrideTTLDefault());
    SetIDWPollingPeriodInNVRAM( psmValue );
    }

    if(g_pHarvester->bIDWReportingPeriodChanged)
    {
    psmValue = g_pHarvester->uIDWReportingPeriod;
    SetIDWReportingPeriod( psmValue );
    SetIDWOverrideTTL(GetIDWOverrideTTLDefault());
    SetIDWReportingPeriodInNVRAM( psmValue );
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        InterfaceDevicesWifi_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
InterfaceDevicesWifi_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));

    if(g_pHarvester->bIDWEnabledChanged)
    {
    g_pHarvester->bIDWEnabled = GetIDWHarvestingStatus();
    g_pHarvester->bIDWEnabledChanged = false;
    }

    if(g_pHarvester->bIDWDefaultPollingPeriodChanged)
    {
        g_pHarvester->uIDWDefaultPollingPeriod = GetIDWPollingPeriodDefault();
        g_pHarvester->bIDWDefaultPollingPeriodChanged = false;
    }
    if(g_pHarvester->bIDWDefaultReportingPeriodChanged)
    {
        g_pHarvester->uIDWDefaultReportingPeriod = GetIDWReportingPeriodDefault();
        g_pHarvester->bIDWDefaultReportingPeriodChanged = false;
    }

    if(g_pHarvester->bIDWPollingPeriodChanged)
    {
    g_pHarvester->uIDWPollingPeriod = GetIDWPollingPeriod();
    g_pHarvester->bIDWPollingPeriodChanged = false;
    }
    if(g_pHarvester->bIDWReportingPeriodChanged)
    {
    g_pHarvester->uIDWReportingPeriod = GetIDWReportingPeriod();
    g_pHarvester->bIDWReportingPeriodChanged = false;
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

    return 0;
}


/**************************************************************************************************************/
/************************************************RadioInterfaceStatistics**************************************/
/**************************************************************************************************************/

BOOL
RadioInterfaceStatistics_GetParamBoolValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    BOOL*                       pBool
)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t rc =-1;
    int ind =-1;

    if(ParamName == NULL)
         return FALSE;

    /* check the parameter name and return the corresponding value */
    rc = strcmp_s("Enabled", strlen("Enabled"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        /* collect value */
        *pBool    =  GetRISHarvestingStatus();
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%d] \n", __FUNCTION__ , ParamName, *pBool ));
        return TRUE;
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
    return FALSE;
}

BOOL
RadioInterfaceStatistics_SetParamBoolValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    BOOL                        bValue
)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t rc =-1;
    int ind =-1;

    if(ParamName == NULL)
         return FALSE;

    /* check the parameter name and set the corresponding value */
    rc = strcmp_s("Enabled", strlen("Enabled"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        g_pHarvester->bRISEnabledChanged = true;
        g_pHarvester->bRISEnabled = bValue;
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%d] \n", __FUNCTION__ , ParamName, bValue ));
        CcspTraceInfo(("RDKB_HARVESTER_VALUE_CHANGED - WiFiRadioInterfaceStats Report %s\n", (bValue) ?  "Enabled" : "Disabled" ));
        return TRUE;
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
    return FALSE;
}


BOOL
RadioInterfaceStatistics_Default_SetParamUlongValue
    (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
    )
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t rc =-1;
    int ind =-1;

    if(ParamName == NULL)
         return FALSE;

    rc = strcmp_s("PollingPeriod", strlen("PollingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        g_pHarvester->bRISDefaultPollingPeriodChanged = true;
        g_pHarvester->uRISDefaultPollingPeriod = uValue;
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, uValue ));
        return TRUE;
    }

    rc =  strcmp_s( "ReportingPeriod",strlen("ReportingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        g_pHarvester->bRISDefaultReportingPeriodChanged = true;
        g_pHarvester->uRISDefaultReportingPeriod = uValue;
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, uValue ));
        return TRUE;
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
    return FALSE;
}


BOOL
RadioInterfaceStatistics_Default_GetParamUlongValue
    (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
    )
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
         return FALSE;

    rc = strcmp_s("PollingPeriod", strlen("PollingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        *puLong =  GetRISPollingPeriodDefault();
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    rc =  strcmp_s( "ReportingPeriod",strlen("ReportingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        *puLong =  GetRISReportingPeriodDefault();
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    rc = strcmp_s("OverrideTTL",strlen("OverrideTTL"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        *puLong =  GetRISOverrideTTLDefault();
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

    return FALSE;
}

BOOL
RadioInterfaceStatistics_GetParamUlongValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    ULONG*                      puLong
)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("PollingPeriod", strlen("PollingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        *puLong =  GetRISPollingPeriod();
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    rc =  strcmp_s( "ReportingPeriod",strlen("ReportingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        *puLong =  GetRISReportingPeriod();
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

    return FALSE;
}

BOOL
RadioInterfaceStatistics_SetParamUlongValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    ULONG                       uValue
)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("PollingPeriod", strlen("PollingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        g_pHarvester->bRISPollingPeriodChanged = true;
        g_pHarvester->uRISPollingPeriod = uValue;
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, uValue ));
        return TRUE;
    }

    rc =  strcmp_s( "ReportingPeriod",strlen("ReportingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        g_pHarvester->bRISReportingPeriodChanged = true;
        g_pHarvester->uRISReportingPeriod = uValue;
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, uValue ));
        return TRUE;
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
    return FALSE;
}

BOOL
RadioInterfaceStatistics_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("Schema", strlen("Schema"),ParamName,&ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        /* collect value */
        int bufsize = GetRISSchemaBufferSize();
        if(!bufsize)
        {
            char result[1024] = "Schema Buffer is empty";
            rc = strcpy_s(pValue,*pUlSize, (char*)&result);
            if(rc != EOK)
            {
               ERR_CHK(rc);
            }
            return FALSE;
        }
        else
    {
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Buffer Size [%d] InputSize [%lu]\n", bufsize, *pUlSize));
        if (bufsize < *pUlSize)
        {
            /*
             * LIMITATION
             * Following AnscCopyString() can't modified to safec strcpy_s() api
             * Because, safec has the limitation of copying only 4k ( RSIZE_MAX ) to destination pointer
             * And here, we have source pointer size more than 4k, i.e simetimes 190k also
            */
            AnscCopyString(pValue, GetRISSchemaBuffer());
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, pValue Buffer Size [%d] \n", (int)strlen(pValue)));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
            return FALSE;
        }
        else
        {
            *pUlSize = bufsize + 1;
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
            return TRUE;
        }
    }
    }

    rc = strcmp_s("SchemaID", strlen("SchemaID"),ParamName,&ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        /* collect value */
        int bufsize = GetRISSchemaIDBufferSize();
        if(!bufsize)
        {
            char result[1024] = "SchemaID Buffer is empty";
            rc = strcpy_s(pValue,*pUlSize, (char*)&result);
            if(rc != EOK)
            {
              ERR_CHK(rc);
            }
            return FALSE;
        }
        else
        {

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Buffer Size [%d] InputSize [%lu]\n", bufsize, *pUlSize));
        if (bufsize < *pUlSize)
        {
            rc = strcpy_s(pValue,*pUlSize, GetRISSchemaIDBuffer());
            if(rc != EOK)
            {
              ERR_CHK(rc);
              return FALSE;
            }
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, pValue Buffer Size [%d] \n", (int)strlen(pValue)));
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
            return FALSE;
        }
        else
        {
            *pUlSize = bufsize + 1;
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
            return TRUE;
        }
    }
    }

    AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

    return FALSE;
}



/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        RadioInterfaceStatistics_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
RadioInterfaceStatistics_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t rc = -1;

    if(g_pHarvester->bRISDefaultPollingPeriodChanged)
    {
        BOOL validated = ValidateRISPeriod(g_pHarvester->uRISDefaultPollingPeriod);    
        if(!validated)
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : PollingPeriod Validation Failed : [%lu] Value not Allowed \n", __FUNCTION__ , g_pHarvester->uRISDefaultPollingPeriod));
           rc =  strcpy_s(pReturnParamName, *puLength, "PollingPeriod");
           if(rc != EOK)
           {
               ERR_CHK(rc);
               return FALSE;
           }
            *puLength = AnscSizeOfString("PollingPeriod");
            return FALSE;
        }
    }

    if(g_pHarvester->bRISDefaultReportingPeriodChanged)
    {
        BOOL validated = ValidateRISPeriod(g_pHarvester->uRISDefaultReportingPeriod);    
        if(!validated)
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : ReportingPeriod Validation Failed : [%lu] Value not Allowed \n", __FUNCTION__ , g_pHarvester->uRISDefaultReportingPeriod));
            rc =strcpy_s(pReturnParamName, *puLength, "ReportingPeriod");
             if(rc != EOK)
             {
               ERR_CHK(rc);
               return FALSE;
             }
            *puLength = AnscSizeOfString("ReportingPeriod");
            return FALSE;
        }
    }

    if(g_pHarvester->bRISPollingPeriodChanged)
    {
        BOOL validated = ValidateRISPeriod(g_pHarvester->uRISPollingPeriod);    
        if(!validated)
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : PollingPeriod Validation Failed : [%lu] Value not Allowed \n", __FUNCTION__ , g_pHarvester->uRISPollingPeriod));
            rc =  strcpy_s(pReturnParamName,*puLength, "PollingPeriod");
            if(rc != EOK)
            {
              ERR_CHK(rc);
              return FALSE;
            }
            *puLength = AnscSizeOfString("PollingPeriod");
            return FALSE;
        }
        if(GetRISHarvestingStatus() && g_pHarvester->uRISPollingPeriod > GetRISPollingPeriod())
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : PollingPeriod Validation Failed : New Polling Period [%lu] > Current Polling Period [%lu] \n", __FUNCTION__ , g_pHarvester->uRISPollingPeriod, GetRISPollingPeriod() ));
            rc =  strcpy_s(pReturnParamName,*puLength, "PollingPeriod");
            if(rc != EOK)
            {
              ERR_CHK(rc);
              return FALSE;
            }
            *puLength = AnscSizeOfString("PollingPeriod");
            return FALSE;           
        }
    
        ULONG period = (g_pHarvester->bRISReportingPeriodChanged == TRUE) ? g_pHarvester->uRISReportingPeriod : GetRISReportingPeriod();

        if(g_pHarvester->uRISPollingPeriod > period)
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : PollingPeriod Validation Failed : New Polling Period [%lu] > Current Reporting Period [%lu] \n", __FUNCTION__ , g_pHarvester->uRISPollingPeriod, period ));
            rc =  strcpy_s(pReturnParamName,*puLength, "PollingPeriod");
            if(rc != EOK)
            {
               ERR_CHK(rc);
               return FALSE;
            }
            *puLength = AnscSizeOfString("PollingPeriod");
            return FALSE;           
        }
    }

    if(g_pHarvester->bRISReportingPeriodChanged)
    {
        BOOL validated = ValidateRISPeriod(g_pHarvester->uRISReportingPeriod);    
        if(!validated)
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : ReportingPeriod Validation Failed : [%lu] Value not Allowed \n", __FUNCTION__ , g_pHarvester->uRISReportingPeriod));
            rc =strcpy_s(pReturnParamName,*puLength, "ReportingPeriod");
            if(rc != EOK)
            {
               ERR_CHK(rc);
               return FALSE;
            }
            *puLength = AnscSizeOfString("ReportingPeriod");
            return FALSE;
        }

        ULONG period = (g_pHarvester->bRISPollingPeriodChanged == TRUE) ? g_pHarvester->uRISPollingPeriod : GetRISPollingPeriod();

        if(g_pHarvester->uRISReportingPeriod < period )
        {
          CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : ReportingPeriod Validation Failed : New Reporting Period [%lu] < Current Polling Period [%lu] \n", __FUNCTION__ , g_pHarvester->uRISReportingPeriod, period ));
            rc =strcpy_s(pReturnParamName,*puLength, "ReportingPeriod");
            if(rc != EOK)
            {
               ERR_CHK(rc);
               return FALSE;
            }
            *puLength = AnscSizeOfString("ReportingPeriod");
            return FALSE;           
        }
        if(GetRISHarvestingStatus() && g_pHarvester->uRISReportingPeriod > GetRISReportingPeriod())
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : ReportingPeriod Validation Failed : New Reporting Period [%lu] > Current Reporting Period [%lu] \n", __FUNCTION__ , g_pHarvester->uRISReportingPeriod, GetRISReportingPeriod() ));
            rc =strcpy_s(pReturnParamName,*puLength, "ReportingPeriod");
            if(rc != EOK)
            {
               ERR_CHK(rc);
               return FALSE;
            }
            *puLength = AnscSizeOfString("ReportingPeriod");
            return FALSE;           
        }
    }

     CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        RadioInterfaceStatistics_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
RadioInterfaceStatistics_Commit
(
    ANSC_HANDLE                 hInsContext
)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    ULONG psmValue = 0;
    /* Network Device Parameters*/

    if(g_pHarvester->bRISEnabledChanged)
    {
    SetRISHarvestingStatus(g_pHarvester->bRISEnabled);
    psmValue = g_pHarvester->bRISEnabled;
    SetNVRamULONGConfiguration(RadioInterfaceStatisticsEnabled, psmValue);
    g_pHarvester->bRISEnabledChanged = false;
    }

    if(g_pHarvester->bRISDefaultPollingPeriodChanged)
    {
    SetRISPollingPeriodDefault(g_pHarvester->uRISDefaultPollingPeriod);
    psmValue = g_pHarvester->uRISDefaultPollingPeriod;
    SetNVRamULONGConfiguration(RadioInterfaceStatisticsDefaultPollingPeriod, psmValue);
    g_pHarvester->bRISDefaultPollingPeriodChanged = false;
    }

    if(g_pHarvester->bRISDefaultReportingPeriodChanged)
    {
    SetRISReportingPeriodDefault(g_pHarvester->uRISDefaultReportingPeriod);
    psmValue = g_pHarvester->uRISDefaultReportingPeriod;
    SetNVRamULONGConfiguration(RadioInterfaceStatisticsDefaultReportingPeriod, psmValue); 
    g_pHarvester->bRISDefaultReportingPeriodChanged = false;
    }

    if(g_pHarvester->bRISPollingPeriodChanged)
    {
    psmValue = g_pHarvester->uRISPollingPeriod;
    SetRISPollingPeriod( psmValue );
    SetRISPollingPeriodInNVRAM( psmValue );
    SetRISOverrideTTL(GetRISOverrideTTLDefault());
    }

    if(g_pHarvester->bRISReportingPeriodChanged)
    {
    psmValue = g_pHarvester->uRISReportingPeriod;
    SetRISReportingPeriod( psmValue );
    SetRISReportingPeriodInNVRAM( psmValue );
    SetRISOverrideTTL(GetRISOverrideTTLDefault());
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        RadioInterfaceStatistics_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
RadioInterfaceStatistics_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));

    if(g_pHarvester->bRISEnabledChanged)
    {
    g_pHarvester->bRISEnabled = GetRISHarvestingStatus();
    g_pHarvester->bRISEnabledChanged = false;
    }

    if(g_pHarvester->bRISDefaultPollingPeriodChanged)
    {
        g_pHarvester->uRISDefaultPollingPeriod = GetRISPollingPeriodDefault();
        g_pHarvester->bRISDefaultPollingPeriodChanged = false;
    }
    if(g_pHarvester->bRISDefaultReportingPeriodChanged)
    {
        g_pHarvester->uRISDefaultReportingPeriod = GetRISReportingPeriodDefault();
        g_pHarvester->bRISDefaultReportingPeriodChanged = false;
    }

    if(g_pHarvester->bRISPollingPeriodChanged)
    {
    g_pHarvester->uRISPollingPeriod = GetRISPollingPeriod();
    g_pHarvester->bRISPollingPeriodChanged = false;
    }
    if(g_pHarvester->bRISReportingPeriodChanged)
    {
    g_pHarvester->uRISReportingPeriod = GetRISReportingPeriod();
    g_pHarvester->bRISReportingPeriodChanged = false;
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

    return 0;
}






/**************************************************************************************************************/
/************************************************Neighboring AP ***********************************************/
/**************************************************************************************************************/



BOOL
NeighboringAP_GetParamBoolValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    BOOL*                       pBool
)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
         return FALSE;

    /* check the parameter name and return the corresponding value */
    rc =  strcmp_s("Enabled", strlen("Enabled"),ParamName, &ind);
    ERR_CHK(rc);
    if ((!ind) && (rc == EOK))
    {
        /* collect value */
        *pBool    =  GetNAPHarvestingStatus();
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%d] \n", __FUNCTION__ , ParamName, *pBool ));
        return TRUE;
    }
    rc =  strcmp_s( "OnDemandScan",strlen("OnDemandScan"),ParamName, &ind);
    ERR_CHK(rc);
    if ((!ind) && (rc == EOK))
    {
        /* collect value */
        *pBool    =  GetNAPOnDemandHarvestingStatus();
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%d] \n", __FUNCTION__ , ParamName, *pBool ));
        return TRUE;
    }
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
    return FALSE;
}

BOOL
NeighboringAP_SetParamBoolValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    BOOL                        bValue
)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    /* check the parameter name and set the corresponding value */
    rc =  strcmp_s("Enabled", strlen("Enabled"),ParamName, &ind);
    ERR_CHK(rc);
    if ((!ind) && (rc == EOK))
    {
        g_pHarvester->bNAPEnabledChanged = true;
        g_pHarvester->bNAPEnabled = bValue;
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%d] \n", __FUNCTION__ , ParamName, bValue ));
        CcspTraceInfo(("RDKB_HARVESTER_VALUE_CHANGED - WiFiNeighbourAP Report %s\n", (bValue) ?  "Enabled" : "Disabled" ));
        return TRUE;
    }
    rc =  strcmp_s( "OnDemandScan",strlen("OnDemandScan"),ParamName, &ind);
    ERR_CHK(rc);
    if ((!ind) && (rc == EOK))
    {
        g_pHarvester->bNAPOnDemandEnabledChanged = true;
        g_pHarvester->bNAPOnDemandEnabled = bValue;
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%d] \n", __FUNCTION__ , ParamName, bValue ));
        return TRUE;
    }
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
    return FALSE;
}


BOOL
NeighboringAP_Default_SetParamUlongValue
    (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
    )
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
         return FALSE;

    rc = strcmp_s("PollingPeriod", strlen("PollingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        g_pHarvester->bNAPDefaultPollingPeriodChanged = true;
        g_pHarvester->uNAPDefaultPollingPeriod = uValue;
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, uValue ));
        return TRUE;
    }

    rc =  strcmp_s( "ReportingPeriod",strlen("ReportingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        g_pHarvester->bNAPDefaultReportingPeriodChanged = true;
        g_pHarvester->uNAPDefaultReportingPeriod = uValue;
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, uValue ));
        return TRUE;
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
    return FALSE;
}


BOOL
NeighboringAP_Default_GetParamUlongValue
    (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
    )
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
         return FALSE;

    rc = strcmp_s("PollingPeriod", strlen("PollingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        *puLong =  GetNAPPollingPeriodDefault();
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    rc =  strcmp_s( "ReportingPeriod",strlen("ReportingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        *puLong =  GetNAPReportingPeriodDefault();
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    rc = strcmp_s("OverrideTTL",strlen("OverrideTTL"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        *puLong =  GetNAPOverrideTTLDefault();
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

    return FALSE;
}

BOOL
NeighboringAP_GetParamUlongValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    ULONG*                      puLong
)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("PollingPeriod", strlen("PollingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        *puLong =  GetNAPPollingPeriod();
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    rc =  strcmp_s( "ReportingPeriod",strlen("ReportingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        *puLong =  GetNAPReportingPeriod();
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, *puLong ));
        return TRUE;
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

    return FALSE;
}

BOOL
NeighboringAP_SetParamUlongValue
(
    ANSC_HANDLE                 hInsContext,
    char*                       ParamName,
    ULONG                       uValue
)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("PollingPeriod", strlen("PollingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        g_pHarvester->bNAPPollingPeriodChanged = true;
        g_pHarvester->uNAPPollingPeriod = uValue;
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, uValue ));
        return TRUE;
    }

    rc =  strcmp_s( "ReportingPeriod",strlen("ReportingPeriod"),ParamName, &ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        g_pHarvester->bNAPReportingPeriodChanged = true;
        g_pHarvester->uNAPReportingPeriod = uValue;
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ParamName[%s] Value[%lu] \n", __FUNCTION__ , ParamName, uValue ));
        return TRUE;
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
    return FALSE;
}

BOOL
NeighboringAP_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("Schema", strlen("Schema"),ParamName,&ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        /* collect value */
        int bufsize = GetNAPSchemaBufferSize();
        if(!bufsize)
        {
            char result[1024] = "Schema Buffer is empty";
            rc = strcpy_s(pValue, *pUlSize, (char*)&result);
            if(rc != EOK)
            {
              ERR_CHK(rc);
            }
            return FALSE;
        }
        else
        {
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Buffer Size [%d] InputSize [%lu]\n", bufsize, *pUlSize));
            if (bufsize < *pUlSize)
            {
                /*
                 * LIMITATION
                 * Following AnscCopyString() can't modified to safec strcpy_s() api
                 * Because, safec has the limitation of copying only 4k ( RSIZE_MAX ) to destination pointer
                 * And here, we have source pointer size more than 4k, i.e simetimes 190k also
                */
                AnscCopyString(pValue, GetNAPSchemaBuffer());
                CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, pValue Buffer Size [%d] \n", (int)strlen(pValue)));
                CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
                return FALSE;
            }
            else
            {
                *pUlSize = bufsize + 1;
                CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
                return TRUE;
            }
        }
    }

    rc = strcmp_s("SchemaID", strlen("SchemaID"),ParamName,&ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        /* collect value */
        int bufsize = GetNAPSchemaIDBufferSize();
        if(!bufsize)
        {
            char result[1024] = "SchemaID Buffer is empty";
            rc =  strcpy_s(pValue,*pUlSize, (char*)&result);
            if(rc != EOK)
            {
              ERR_CHK(rc);
            }
            return FALSE;
        }
        else
        {

        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Buffer Size [%d] InputSize [%lu]\n", bufsize, *pUlSize));

            if (bufsize < *pUlSize)
            {
                rc =  strcpy_s(pValue,*pUlSize, GetNAPSchemaIDBuffer());
                if(rc != EOK)
                {
                   ERR_CHK(rc);
                   return FALSE;
                }
                CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, pValue Buffer Size [%d] \n", (int)strlen(pValue)));
                CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
                return FALSE;
            }
            else
            {
                *pUlSize = bufsize + 1;
                CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
                return TRUE;
            }
        }
    }

    rc = strcmp_s("LastScanData", strlen("LastScanData"),ParamName,&ind);
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        size_t decodesize = b64_get_encoded_buffer_size( GetNeighborAPAvroBufSize() );

        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Decoded Size [%d] Input Size [%ld] \n", (int)decodesize, *pUlSize));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Buffer Size [%d] \n", (int)strlen(pValue)));
        
        if(!decodesize)
        {
            char result[1024] = "NeighborAP Buffer is empty";
            rc= strcpy_s(pValue,*pUlSize, (char*)&result);
            if(rc != EOK)
            {
               ERR_CHK(rc);
            }
            return FALSE;
        }
        else
        {
            /* collect value */
            if (decodesize < *pUlSize)
            {
                uint8_t* base64buffer = malloc((*pUlSize) * sizeof(uint8_t));
                 /*Coverity Fix CID:72050 NULL_RETURNS */
                if(base64buffer != NULL)
                { 
                  b64_encode( (uint8_t*)GetNeighborAPAvroBuf(), GetNeighborAPAvroBufSize(), base64buffer);
                  base64buffer[(*pUlSize) - 1] = '\0';
                  /*
                   * LIMITATION
                   * Following AnscCopyString() can't modified to safec strcpy_s() api
                   * Because, safec has the limitation of copying only 4k ( RSIZE_MAX ) to destination pointer
                   * And here, we have source pointer size more than 4k, i.e simetimes 190k also
                  */
                  AnscCopyString(pValue, (char*)base64buffer);
                  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, pValue Buffer Size [%d] \n", (int)strlen(pValue)));
                  free(base64buffer);
                }
                else
                {                
                        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s  : base64buffer NULL_RETURNS \n", __FUNCTION__ ));
                }       
                CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
                return FALSE;
            }
            else
            {
                *pUlSize = decodesize+1;
                CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
                return TRUE;
            }
        }
    }

    AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

    return FALSE;
}



/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        NeighboringAP_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
NeighboringAP_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    errno_t rc = -1;

    if(g_pHarvester->bNAPDefaultPollingPeriodChanged)
    {
        BOOL validated = ValidateNAPPeriod(g_pHarvester->uNAPDefaultPollingPeriod);    
        if(!validated)
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : PollingPeriod Validation Failed : [%lu] Value not Allowed \n", __FUNCTION__ , g_pHarvester->uNAPDefaultPollingPeriod));
            rc =  strcpy_s(pReturnParamName,*puLength, "PollingPeriod");
            if(rc != EOK)
            {
              ERR_CHK(rc);
              return FALSE;
            }
           *puLength = AnscSizeOfString("PollingPeriod");
            return FALSE;
        }
    }

    if(g_pHarvester->bNAPDefaultReportingPeriodChanged)
    {
        BOOL validated = ValidateNAPPeriod(g_pHarvester->uNAPDefaultReportingPeriod);    
        if(!validated)
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : ReportingPeriod Validation Failed : [%lu] Value not Allowed \n", __FUNCTION__ , g_pHarvester->uNAPDefaultReportingPeriod));
            rc =  strcpy_s(pReturnParamName,*puLength, "ReportingPeriod");
            if(rc != EOK)
            {
              ERR_CHK(rc);
              return FALSE;
            }
           *puLength = AnscSizeOfString("ReportingPeriod");
            return FALSE;
        }
    }

    if(g_pHarvester->bNAPPollingPeriodChanged)
    {
        BOOL validated = ValidateNAPPeriod(g_pHarvester->uNAPPollingPeriod);    
        if(!validated)
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : PollingPeriod Validation Failed : [%lu] Value not Allowed \n", __FUNCTION__ , g_pHarvester->uNAPPollingPeriod));
            rc =  strcpy_s(pReturnParamName,*puLength, "PollingPeriod");
            if(rc != EOK)
            {
               ERR_CHK(rc);
               return FALSE;
            }
            *puLength = AnscSizeOfString("PollingPeriod");
            return FALSE;
        }
        if(GetNAPHarvestingStatus() && g_pHarvester->uNAPPollingPeriod > GetNAPPollingPeriod())
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : PollingPeriod Validation Failed : New Polling Period [%lu] > Current Polling Period [%lu] \n", __FUNCTION__ , g_pHarvester->uNAPPollingPeriod, GetNAPPollingPeriod() ));
            rc =  strcpy_s(pReturnParamName,*puLength, "PollingPeriod");
            if(rc != EOK)
            {
               ERR_CHK(rc);
               return FALSE;
            }
            *puLength = AnscSizeOfString("PollingPeriod");
            return FALSE;           
        }

        ULONG period = (g_pHarvester->bNAPReportingPeriodChanged == TRUE) ? g_pHarvester->uNAPReportingPeriod : GetNAPReportingPeriod();

        if(g_pHarvester->uNAPPollingPeriod > period )
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : PollingPeriod Validation Failed : New Polling Period [%lu] > Current Reporting Period [%lu] \n", __FUNCTION__ , g_pHarvester->uNAPPollingPeriod, period ));
            rc =  strcpy_s(pReturnParamName,*puLength, "PollingPeriod");
            if(rc != EOK)
            {
              ERR_CHK(rc);
              return FALSE;
            }
            *puLength = AnscSizeOfString("PollingPeriod");
            return FALSE;           
        }
    }

    if(g_pHarvester->bNAPReportingPeriodChanged)
    {
        BOOL validated = ValidateNAPPeriod(g_pHarvester->uNAPReportingPeriod);    
        if(!validated)
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : ReportingPeriod Validation Failed : [%lu] Value not Allowed \n", __FUNCTION__ , g_pHarvester->uNAPReportingPeriod));
            rc =  strcpy_s(pReturnParamName,*puLength, "ReportingPeriod");
            if(rc != EOK)
            { 
              ERR_CHK(rc);
              return FALSE;
            }
            *puLength = AnscSizeOfString("ReportingPeriod");
            return FALSE;
        }

        ULONG period = (g_pHarvester->bNAPPollingPeriodChanged == TRUE) ? g_pHarvester->uNAPPollingPeriod : GetNAPPollingPeriod();

        if(g_pHarvester->uNAPReportingPeriod < period )
        {
           CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : ReportingPeriod Validation Failed : New Reporting Period [%lu] < Current Polling Period [%lu] \n", __FUNCTION__ , g_pHarvester->uNAPReportingPeriod, period ));
            rc =  strcpy_s(pReturnParamName,*puLength, "ReportingPeriod");
            if(rc != EOK)
            {
               ERR_CHK(rc);
               return FALSE;
            }
            *puLength = AnscSizeOfString("ReportingPeriod");
            return FALSE;           
        }
        if(GetNAPHarvestingStatus() && g_pHarvester->uNAPReportingPeriod > GetNAPReportingPeriod())
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : ReportingPeriod Validation Failed : New Reporting Period [%lu] > Current Reporting Period [%lu] \n", __FUNCTION__ , g_pHarvester->uNAPReportingPeriod, GetNAPReportingPeriod() ));
            rc =  strcpy_s(pReturnParamName,*puLength, "ReportingPeriod");
            if(rc != EOK)
            {
              ERR_CHK(rc);
              return FALSE;
            }
            *puLength = AnscSizeOfString("ReportingPeriod");
            return FALSE;           
        }
    }

     CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        NeighboringAP_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
NeighboringAP_Commit
(
    ANSC_HANDLE                 hInsContext
)
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
    ULONG psmValue = 0;
    /* Network Device Parameters*/

    if(g_pHarvester->bNAPEnabledChanged)
    {
    SetNAPHarvestingStatus(g_pHarvester->bNAPEnabled);
    psmValue = g_pHarvester->bNAPEnabled;
    SetNVRamULONGConfiguration(NeighboringAPEnabled, psmValue);
    g_pHarvester->bNAPEnabledChanged = false;
    }

    if(g_pHarvester->bNAPDefaultPollingPeriodChanged)
    {
    SetNAPPollingPeriodDefault(g_pHarvester->uNAPDefaultPollingPeriod);
    psmValue = g_pHarvester->uNAPDefaultPollingPeriod;
    SetNVRamULONGConfiguration(NeighboringAPDefaultPollingPeriod, psmValue);
    g_pHarvester->bNAPDefaultPollingPeriodChanged = false;
    }

    if(g_pHarvester->bNAPDefaultReportingPeriodChanged)
    {
    SetNAPReportingPeriodDefault(g_pHarvester->uNAPDefaultReportingPeriod);
    psmValue = g_pHarvester->uNAPDefaultReportingPeriod;
    SetNVRamULONGConfiguration(NeighboringAPDefaultReportingPeriod, psmValue);  
    g_pHarvester->bNAPDefaultReportingPeriodChanged = false;
    }

    if(g_pHarvester->bNAPPollingPeriodChanged)
    {
    psmValue = g_pHarvester->uNAPPollingPeriod;
    SetNAPPollingPeriod( psmValue );
    SetNAPPollingPeriodInNVRAM( psmValue );
    SetNAPOverrideTTL(GetNAPOverrideTTLDefault());
    }

    if(g_pHarvester->bNAPReportingPeriodChanged)
    {
    psmValue = g_pHarvester->uNAPReportingPeriod;
    SetNAPReportingPeriod( psmValue );
    SetNAPReportingPeriodInNVRAM( psmValue );
    SetNAPOverrideTTL(GetNAPOverrideTTLDefault());
    }

    if(g_pHarvester->bNAPOnDemandEnabledChanged)
    {
    SetNAPOnDemandHarvestingStatus(g_pHarvester->bNAPOnDemandEnabled);
    g_pHarvester->bNAPOnDemandEnabledChanged = false;
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));
    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        NeighboringAP_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
NeighboringAP_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));

    if(g_pHarvester->bNAPEnabledChanged)
    {
    g_pHarvester->bNAPEnabled = GetNAPHarvestingStatus();
    g_pHarvester->bNAPEnabledChanged = false;
    }

    if(g_pHarvester->bNAPDefaultPollingPeriodChanged)
    {
        g_pHarvester->uNAPDefaultPollingPeriod = GetNAPPollingPeriodDefault();
        g_pHarvester->bNAPDefaultPollingPeriodChanged = false;
    }
    if(g_pHarvester->bNAPDefaultReportingPeriodChanged)
    {
        g_pHarvester->uNAPDefaultReportingPeriod = GetNAPReportingPeriodDefault();
        g_pHarvester->bNAPDefaultReportingPeriodChanged = false;
    }

    if(g_pHarvester->bNAPPollingPeriodChanged)
    {
    g_pHarvester->uNAPPollingPeriod = GetNAPPollingPeriod();
    g_pHarvester->bNAPPollingPeriodChanged = false;
    }
    if(g_pHarvester->bNAPReportingPeriodChanged)
    {
    g_pHarvester->uNAPReportingPeriod = GetNAPReportingPeriod();
    g_pHarvester->bNAPReportingPeriodChanged = false;
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

    return 0;
}

