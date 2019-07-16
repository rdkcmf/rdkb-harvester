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
#include "ansc_load_library.h"
#include "cosa_plugin_api.h"
#include "plugin_main.h"
#include "cosa_harvester_dml.h"
#include "cosa_harvester_internal.h"

#define THIS_PLUGIN_VERSION                         1

COSA_DATAMODEL_HARVESTER* g_pHarvester = NULL;

int ANSC_EXPORT_API
COSA_Init
    (
        ULONG                       uMaxVersionSupported, 
        void*                       hCosaPlugInfo         /* PCOSA_PLUGIN_INFO passed in by the caller */
    )
{
    PCOSA_PLUGIN_INFO               pPlugInfo  = (PCOSA_PLUGIN_INFO)hCosaPlugInfo;

    if ( uMaxVersionSupported < THIS_PLUGIN_VERSION )
    {
      /* this version is not supported */
        return -1;
    }   
    
    pPlugInfo->uPluginVersion       = THIS_PLUGIN_VERSION;
    /* register the back-end apis for the data model */
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "InterfaceDevicesWifi_GetParamUlongValue",  InterfaceDevicesWifi_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "InterfaceDevicesWifi_GetParamBoolValue",  InterfaceDevicesWifi_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "InterfaceDevicesWifi_GetParamStringValue",  InterfaceDevicesWifi_GetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "InterfaceDevicesWifi_SetParamBoolValue",  InterfaceDevicesWifi_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "InterfaceDevicesWifi_SetParamUlongValue",  InterfaceDevicesWifi_SetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "InterfaceDevicesWifi_Validate",  InterfaceDevicesWifi_Validate);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "InterfaceDevicesWifi_Commit",  InterfaceDevicesWifi_Commit);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "InterfaceDevicesWifi_Rollback",  InterfaceDevicesWifi_Rollback);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "InterfaceDevicesWifi_Default_GetParamUlongValue",  InterfaceDevicesWifi_Default_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "InterfaceDevicesWifi_Default_SetParamUlongValue",  InterfaceDevicesWifi_Default_SetParamUlongValue);


    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RadioInterfaceStatistics_GetParamUlongValue",  RadioInterfaceStatistics_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RadioInterfaceStatistics_GetParamBoolValue",  RadioInterfaceStatistics_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RadioInterfaceStatistics_GetParamStringValue",  RadioInterfaceStatistics_GetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RadioInterfaceStatistics_SetParamBoolValue",  RadioInterfaceStatistics_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RadioInterfaceStatistics_SetParamUlongValue",  RadioInterfaceStatistics_SetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RadioInterfaceStatistics_Validate",  RadioInterfaceStatistics_Validate);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RadioInterfaceStatistics_Commit",  RadioInterfaceStatistics_Commit);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RadioInterfaceStatistics_Rollback",  RadioInterfaceStatistics_Rollback);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RadioInterfaceStatistics_Default_GetParamUlongValue",  RadioInterfaceStatistics_Default_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RadioInterfaceStatistics_Default_SetParamUlongValue",  RadioInterfaceStatistics_Default_SetParamUlongValue);


    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "NeighboringAP_GetParamUlongValue",  NeighboringAP_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "NeighboringAP_GetParamBoolValue",  NeighboringAP_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "NeighboringAP_GetParamStringValue",  NeighboringAP_GetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "NeighboringAP_SetParamBoolValue",  NeighboringAP_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "NeighboringAP_SetParamUlongValue",  NeighboringAP_SetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "NeighboringAP_Validate",  NeighboringAP_Validate);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "NeighboringAP_Commit",  NeighboringAP_Commit);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "NeighboringAP_Rollback",  NeighboringAP_Rollback);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "NeighboringAP_Default_GetParamUlongValue",  NeighboringAP_Default_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "NeighboringAP_Default_SetParamUlongValue",  NeighboringAP_Default_SetParamUlongValue);

 
     /* Create Harvester Object for Settings */
    g_pHarvester = (PCOSA_DATAMODEL_HARVESTER)CosaHarvesterCreate();

    if ( g_pHarvester )
    {
        // print success
        CosaHarvesterInitialize(g_pHarvester);
    }

    return  0;
}

BOOL ANSC_EXPORT_API
COSA_IsObjectSupported
    (
        char*                        pObjName
    )
{
    
    return TRUE;
}

void ANSC_EXPORT_API
COSA_Unload
    (
        void
    )
{
    /* unload the memory here */
    if ( g_pHarvester )
    {
        // print success
        CosaHarvesterRemove(g_pHarvester);
    }

    g_pHarvester = NULL;
}
