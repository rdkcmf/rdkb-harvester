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

#ifndef  HARVESTER_ASSOCIATED_DEVICES_H
#define  HARVESTER_ASSOCIATED_DEVICES_H

#include "ansc_platform.h"

/**
 * @brief Set the Harvesting Status for Associated Devices.
 *
 * @param[in] status New Harvesting Status.
 * @return status 0 for success and 1 for failure
 */
int SetIDWHarvestingStatus(BOOL status);

/**
 * @brief Gets the Harvesting Status for Associated Devices.
 *
 * @return status true if enabled and false if disabled
 */
BOOL GetIDWHarvestingStatus();

/**
 * @brief Set the Reporting Period for Associated Devices Scan.
 *
 * @param[in] interval Time in Seconds.
 * @return status 0 for success and 1 for failure
 */
int SetIDWReportingPeriod(ULONG interval);

/**
 * @brief Gets the Associated Devices Reporting Period
 *
 * @return interval : The Current Reporting Period
 */
ULONG GetIDWReportingPeriod();

/**
 * @brief Set the Polling Period for Associated Devices Scan.
 *
 * @param[in] interval Time in Seconds.
 * @return status 0 for success and 1 for failure
 */
int SetIDWPollingPeriod(ULONG interval);

/**
 * @brief Gets the Associated Devices Polling Period
 *
 * @return interval : The Current Polling Period
 */
ULONG GetIDWPollingPeriod();

/**
 * @brief Set the Default Reporting Period for Associated Devices Scan.
 *
 * @param[in] interval Time in Seconds.
 * @return status 0 for success and 1 for failure
 */
int SetIDWReportingPeriodDefault(ULONG interval);

/**
 * @brief Gets the Default Associated Devices Reporting Period
 *
 * @return interval : The Current Reporting Period
 */
ULONG GetIDWReportingPeriodDefault();

/**
 * @brief Set the Default Polling Period for Associated Devices Scan.
 *
 * @param[in] interval Time in Seconds.
 * @return status 0 for success and 1 for failure
 */
int SetIDWPollingPeriodDefault(ULONG interval);

/**
 * @brief Gets the Default Associated Devices Polling Period
 *
 * @return interval : The Current Reporting Period
 */
ULONG GetIDWPollingPeriodDefault();

/**
 * @brief Gets the timeout after which the IDW intervals return to default values
 *
 * @return timeout : The Current timeout in seconds
 */
ULONG GetIDWOverrideTTL();

/**
 * @brief Set the timeout for IDW Scans for which the accelerated polling will take place .
 *
 * @param[in] timeout Time in Seconds.
 * @return status 0 for success and 1 for failure
 */
int SetIDWOverrideTTL(ULONG count);

/**
 * @brief Gets the Default timeout for Accelerated Scans
 *
 * @return interval : The default timeout
 */
ULONG GetIDWOverrideTTLDefault();

/**
 * @brief Validated the Period Values for IDW Scan and makes sure they are 
 *        present in the valid range of Values.
 *
 * @param[in] interval interval to be validated.
 * @return status 0 for success and 1 for failure
 */
BOOL ValidateIDWPeriod(ULONG interval);

BOOL isvalueinarray(ULONG val, ULONG *arr, int size);

#ifdef RDK_ONEWIFI
/**
 * @brief Extract the radioIndex value from the given string input
 *
 * @param[in] String with radioindex value.
 * @return radio index value
 */
int parseInputValue(char * value);
#endif
#endif 
