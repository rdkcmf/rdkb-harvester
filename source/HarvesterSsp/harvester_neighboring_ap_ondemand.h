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

#ifndef  HARVESTER_NEIGHBORING_AP_ONDEMAND_H
#define  HARVESTER_NEIGHBORING_AP_ONDEMAND_H

#include "ansc_platform.h"

/**
 * @brief Set the Harvesting Status for Neighbor AP On Demand Scans.
 *
 * @param[in] status New Harvesting Status.
 * @return status 0 for success and 1 for failure
 */
int SetNAPOnDemandHarvestingStatus(BOOL status);

/**
 * @brief Gets the Harvesting Status for Neighboring AP On Demand Scans.
 *
 * @return status true if enabled and false if disabled
 */
BOOL GetNAPOnDemandHarvestingStatus();

#endif 
