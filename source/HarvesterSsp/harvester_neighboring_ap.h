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

#ifndef  HARVESTER_NEIGHBORING_AP_H
#define  HARVESTER_NEIGHBORING_AP_H

#include "ansc_platform.h"

/**
 * @brief Set the Harvesting Status for Neighboring AP Scans.
 *
 * @param[in] status New Harvesting Status.
 * @return status 0 for success and 1 for failure
 */
int SetNAPHarvestingStatus(BOOL status);

/**
 * @brief Gets the Harvesting Status for Neighboring AP Scans.
 *
 * @return status true if enabled and false if disabled
 */
BOOL GetNAPHarvestingStatus();

/**
 * @brief Set the Reporting Period for Neighboring AP Scan.
 *
 * @param[in] interval Time in Seconds.
 * @return status 0 for success and 1 for failure
 */
int SetNAPReportingPeriod(ULONG interval);

/**
 * @brief Gets the Neighboring AP RepoNAPing Period
 *
 * @return interval : The Current Reporting Period
 */
ULONG GetNAPReportingPeriod();

/**
 * @brief Set the Polling Period for Neighboring AP Scan.
 *
 * @param[in] interval Time in Seconds.
 * @return status 0 for success and 1 for failure
 */
int SetNAPPollingPeriod(ULONG interval);

/**
 * @brief Gets the Neighboring AP Polling Period
 *
 * @return interval : The Current Polling Period
 */
ULONG GetNAPPollingPeriod();

/**
 * @brief Set the Default Reporting Period for Neighboring AP Scan.
 *
 * @param[in] interval Time in Seconds.
 * @return status 0 for success and 1 for failure
 */
int SetNAPReportingPeriodDefault(ULONG interval);

/**
 * @brief Gets the Default Neighboring AP Reporting Period
 *
 * @return interval : The Current Reporting Period
 */
ULONG GetNAPReportingPeriodDefault();

/**
 * @brief Set the Default Polling Period for Neighboring AP Scan.
 *
 * @param[in] interval Time in Seconds.
 * @return status 0 for success and 1 for failure
 */
int SetNAPPollingPeriodDefault(ULONG interval);

/**
 * @brief Gets the Default Neighboring AP Polling Period
 *
 * @return interval : The Current Reporting Period
 */
ULONG GetNAPPollingPeriodDefault();

/**
 * @brief Gets the timeout after which the NAP intervals return to default values
 *
 * @return timeout : The Current timeout in seconds
 */
ULONG GetNAPOverrideTTL();

/**
 * @brief Set the timeout for NAP Scans for which the accelerated polling will take place .
 *
 * @param[in] timeout Time in Seconds.
 * @return status 0 for success and 1 for failure
 */
int SetNAPOverrideTTL(ULONG count);

/**
 * @brief Gets the Default timeout for Accelerated Scans
 *
 * @return interval : The default timeout
 */
ULONG GetNAPOverrideTTLDefault();

/**
 * @brief Validated the Period Values for NAP Scan and makes sure they are 
 *        present in the valid range of Values.
 *
 * @param[in] interval interval to be validated.
 * @return status 0 for success and 1 for failure
 */
BOOL ValidateNAPPeriod(ULONG interval);


#endif 
