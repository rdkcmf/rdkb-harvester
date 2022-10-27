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

#ifndef  HARVESTER_RBUS_API_H
#define  HARVESTER_RBUS_API_H

#include "ansc_platform.h"
#include "harvester_avro.h"
#include <rbus/rbus.h>

/**
 * @brief Gets the rbus_handle for harvester.
 *
 * @return rbusHandle_t value
 */
rbusHandle_t get_rbus_handle(void);

/**
 * @brief Gets the rbus initialized status.
 *
 * @return status true for rbus is initialized and false for not initialized
 */
bool rbusInitializedCheck();

/**
 * @brief Initializes the Rbus with component name given.
 *
 * @param[in] pComponentName Harvester component name.
 *
 * @return status 0 for intialization is success or 1 for initialization is failure
 */
int harvesterRbusInit(const char *pComponentName);

/**
 * @brief Uninitializes the registered harvester component.
 */
void harvesterRbus_Uninit();

/**
 * @brief Gets the Bool value for a given indexed Tr181 Path.
 *
 * @param[out] value to receive the bool value.
 *
 * @param[in] path TR181 name from which bool value is obtained.
 *
 * @return status 0 for success or 1 for failure
 */
int rbus_getBoolValue(BOOL * value, char * path);

/**
 * @brief Gets the String value for a given indexed Tr181 Path.
 *
 * @param[out] value to receive the string value.
 *
 * @param[in] path TR181 name from which string value is obtained.
 *
 * @return status 0 for success or 1 for failure
 */
int rbus_getStringValue(char * value, char * path);

/**
 * @brief Gets the Uint value for a given indexed Tr181 Path.
 *
 * @param[out] value to receive the uint32 value.
 *
 * @param[in] path TR181 name from which Uint value is obtained.
 *
 * @return status 0 for success or 1 for failure
 */
int rbus_getUInt32Value(ULONG * value, char * path);

/**
 * @brief To Fetch the required ApAssociatedDeviceDiagnosticResult values using Rbus.
 *
 * @param[out] dev to store the wifi_associated_dev_t struct values.
 *
 * @param[out] assocDevCount to get the total number of client devices connected.
 *
 * @param[in] index to input the SSID index value.
 *
 * @return status 0 for success or 1 for failure
 */
int rbus_getApAssociatedDeviceDiagnosticResult(int index, wifi_associated_dev_t** dev, uint32_t *assocDevCount);

/**
 * @brief To Fetch the required RadioTrafficStats values using Rbus.
 *
 * @param[out] output_struct to store the wifi_radioTrafficStats2_t struct values.
 *
 * @param[out] assocDevCount to get the total number of client devices connected.
 *
 * @param[in] radioIndex to input the radio index value.
 *
 * @return status 0 for success or 1 for failure
 */
int rbus_wifi_getRadioTrafficStats2(int radioIndex, wifi_radioTrafficStats2_t *output_struct);

/**
 * @brief To Fetch the required NeighboringWiFiDiagnostic result values using Rbus.
 *
 * @param[out] neighbor_ap_array to store the wifi_neighbor_ap2_t struct value.
 *
 * @param[out] array_size to get the Neighboring AP Array Size.
 *
 * @param[in] executed bool flag true if Neighboring on demand report is done or 
 *
 *             false if Neighboring on demand report is not done yet.
 *
 * @return status 0 for success or 1 for failure
 */
int rbus_wifi_getNeighboringWiFiDiagnosticResult2(bool *executed, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *array_size);
#endif
