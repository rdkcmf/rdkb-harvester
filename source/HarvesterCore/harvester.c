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
   
#include <stdio.h>
#include "ansc_platform.h"
#include "harvester.h"
#if defined(_INTEL_WAV_)
#include "wifi_hal.h"
#endif

int consoleDebugEnable = 0;
FILE* debugLogFile;

int main(int argc, char* argv[])
{
    debugLogFile = stderr;

    int idx = 0;
    for (idx = 0; idx < argc; idx++)
    {
        if ( (strcmp(argv[idx], "-DEBUG") == 0) )
        {
            consoleDebugEnable = 1;
            fprintf(stderr, "DEBUG ENABLE ON \n");
        }
        else if ( (strcmp(argv[idx], "-LOGFILE") == 0) )
        {
            // We assume argv[1] is a filename to open
            debugLogFile = fopen( argv[idx + 1], "a+" );

            /* fopen returns 0, the NULL pointer, on failure */
            if ( debugLogFile == 0 )
            {
                debugLogFile = stderr;
                fprintf(debugLogFile, "Invalid Entry for -LOGFILE input \n" );
            }
            else 
            {
                fprintf(debugLogFile, "Log File [%s] Opened for Writing in Append Mode \n",  argv[idx+1]);
            }

        }
    }

    fprintf(stderr, "RDK_LOG_DEBUG, Registering Harvester component '%s' with CR ..\n", HARVESTER_COMPONENT_NAME);

    msgBusInit(HARVESTER_COMPONENT_NAME);
       
    fprintf(stderr, "RDK_LOG_DEBUG, Registered Harvester component '%s' with CR ..\n", HARVESTER_COMPONENT_NAME);
#if defined(_INTEL_WAV_)
    ULONG output = 0;
    int ret =  wifi_getRadioNumberOfEntries(&output);
    if(!ret && output > 0)
    {
        for (int k = 0; k < output; k++)
        {
            ret = wifi_hostapNlConnect(k);
            if (ret)
            {
                fprintf(stderr, "RDK_LOG_ERROR, wifi_hostapNlConnect(%d) Error returned [%d] \n", k, ret);
            }
        }
    }
    else
    {
        fprintf(stderr, "RDK_LOG_WARN, wifi_getRadioNumberOfEntries Error [%d] or No radios detected [%ld] \n", ret, output);
    }
#endif
    initparodusTask();
    while(1)
    {
        sleep(30);
    }

    if(debugLogFile)
    {
        fclose(debugLogFile);
    }

    fprintf(stderr, "RDK_LOG_DEBUG, Harvester %s EXIT\n", __FUNCTION__ );

    return 0;
}

