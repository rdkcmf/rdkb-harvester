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

#ifndef  HARVESTER_RADIOTRAFFIC_H
#define  HARVESTER_RADIOTRAFFIC_H

#include "ansc_platform.h"

/**
 * @brief Set the Harvesting Status for Radio Traffic Scans.
 *
 * @param[in] status New Harvesting Status.
 * @return status 0 for success and 1 for failure
 */
int SetRISHarvestingStatus(BOOL status);

/**
 * @brief Gets the Harvesting Status for Radio Traffic Scans.
 *
 * @return status true if enabled and false if disabled
 */
BOOL GetRISHarvestingStatus();

/**
 * @brief Set the Reporting Period for Radio Traffic Scan.
 *
 * @param[in] interval Time in Seconds.
 * @return status 0 for success and 1 for failure
 */
int SetRISReportingPeriod(ULONG interval);

/**
 * @brief Gets the Radio Traffic Reporting Period
 *
 * @return interval : The Current Reporting Period
 */
ULONG GetRISReportingPeriod();

/**
 * @brief Set the Polling Period for Radio Traffic Scan.
 *
 * @param[in] interval Time in Seconds.
 * @return status 0 for success and 1 for failure
 */
int SetRISPollingPeriod(ULONG interval);

/**
 * @brief Gets the Radio Traffic Polling Period
 *
 * @return interval : The Current Polling Period
 */
ULONG GetRISPollingPeriod();

/**
 * @brief Set the Default Reporting Period for Radio Traffic Scan.
 *
 * @param[in] interval Time in Seconds.
 * @return status 0 for success and 1 for failure
 */
int SetRISReportingPeriodDefault(ULONG interval);

/**
 * @brief Gets the Default Radio Traffic Reporting Period
 *
 * @return interval : The Current Reporting Period
 */
ULONG GetRISReportingPeriodDefault();

/**
 * @brief Set the Default Polling Period for Radio Traffic Scan.
 *
 * @param[in] interval Time in Seconds.
 * @return status 0 for success and 1 for failure
 */
int SetRISPollingPeriodDefault(ULONG interval);

/**
 * @brief Gets the Default Radio Traffic Polling Period
 *
 * @return interval : The Current Reporting Period
 */
ULONG GetRISPollingPeriodDefault();

/**
 * @brief Gets the timeout after which the RIS intervals return to default values
 *
 * @return timeout : The Current timeout in seconds
 */
ULONG GetRISOverrideTTL();

/**
 * @brief Set the timeout for RIS Scans for which the accelerated polling will take place .
 *
 * @param[in] timeout Time in Seconds.
 * @return status 0 for success and 1 for failure
 */
int SetRISOverrideTTL(ULONG count);

/**
 * @brief Gets the Default timeout for Accelerated Scans
 *
 * @return interval : The default timeout
 */
ULONG GetRISOverrideTTLDefault();

/**
 * @brief Validated the Period Values for RIS Scan and makes sure they are 
 *        present in the valid range of Values.
 *
 * @param[in] interval interval to be validated.
 * @return status 0 for success and 1 for failure
 */
BOOL ValidateRISPeriod(ULONG interval);

#endif 
