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
/**
* @file ssp_main.c
* 
* @description This file is used to manage the dbus call and stack trace.
*
*/
#ifdef __GNUC__
#ifndef _BUILD_ANDROID
#include <execinfo.h>
#endif
#endif

#include "ssp_global.h"
#include "stdlib.h"
#include "ccsp_dm_api.h"
#include "harvester.h"
#include "ccsp_custom_logs.h"
#include "ccsp_harvesterLog_wrapper.h"
/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/
#define DEBUG_INI_NAME "/etc/debug.ini"

/*----------------------------------------------------------------------------*/
/*                               File scoped variables                              */
/*----------------------------------------------------------------------------*/
char  g_Subsystem[32] = {0};
extern char*                                pComponentName;
/*----------------------------------------------------------------------------*/
/*                             Function Prototypes                            */
/*----------------------------------------------------------------------------*/
static void daemonize(void);


/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/

/**
 * @brief This functionality helps in approaching the bus deamon to create and engage the components.
 */
int  cmd_dispatch(int  command)
{
    switch ( command )
    {
        case    'e' :

#ifdef _ANSC_LINUX
            CcspTraceInfo(("Connect to bus daemon...\n"));

            {
                char                            CName[256];

                if ( g_Subsystem[0] != 0 )
                {
                    _ansc_sprintf(CName, "%s%s", g_Subsystem, CCSP_COMPONENT_ID);
                }
                else
                {
                    _ansc_sprintf(CName, "%s", CCSP_COMPONENT_ID);
                }

                ssp_Mbi_MessageBusEngage
                    ( 
                        CName,
                        CCSP_MSG_BUS_CFG,
                        CCSP_COMPONENT_PATH
                    );
            }
#endif

            ssp_create();
            ssp_engage();

            break;

        case    'm':

                AnscPrintComponentMemoryTable(pComponentName);

                break;

        case    't':

                AnscTraceMemoryTable();

                break;

        case    'c':
                
                ssp_cancel();

                break;

        default:
            break;
    }

    return 0;
}

/**
 * @brief Bus platform initialization to engage the component to CR(Component Registrar).
 */
int msgBusInit(const char *name)
{
    BOOL                            bRunAsDaemon       = TRUE;
    int                             cmdChar            = 0;
	
    extern ANSC_HANDLE bus_handle;
    char *subSys            = NULL;  
    DmErr_t    err;
    AnscCopyString(g_Subsystem, "eRT.");
    pComponentName = name;
    if ( bRunAsDaemon ) 
        daemonize();

    cmd_dispatch('e');

    subSys = NULL;      /* use default sub-system */

    err = Cdm_Init(bus_handle, subSys, NULL, NULL, pComponentName);
    if (err != CCSP_SUCCESS)
    {
        fprintf(stderr, "Cdm_Init: %s\n", Cdm_StrError(err));
        exit(1);
    }
    
    #ifdef FEATURE_SUPPORT_RDKLOG
        int ret = rdk_logger_init(DEBUG_INI_NAME);
        if(ret == 0)
        {
            CcspHarvesterTrace(("RDK_LOG_INFO, rdk-logger initialzed!\n"));
        }
        else
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Failed to initialize rdk-logger\n"));
        }
    #endif
    
    system("touch /tmp/harvester_initialized");
    printf("Inside msgBusInit : /tmp/harvester_initialized created\n");
    CcspTraceInfo(("RDK_LOG_WARN, HARV : /tmp/harvester_initialized created\n"));
    CcspHarvesterTrace(("RDK_LOG_WARN,  HARV : /tmp/harvester_initialized created\n"));
    if ( bRunAsDaemon )
    {
        return 1; //Failure
    }
    else
    {
        while ( cmdChar != 'q' )
        {
            cmdChar = getchar();

            cmd_dispatch(cmdChar);
        }
    }

    err = Cdm_Term();
    if (err != CCSP_SUCCESS)
    {
    fprintf(stderr, "Cdm_Term: %s\n", Cdm_StrError(err));
    exit(1);
    }

    ssp_cancel();
    return 0; //Success
}

void HarvesterLog(char *msg)
{
    char LogMsg_arr[4096] = {0};
    char *LogMsg = LogMsg_arr;
    char LogLevel[4096] = {0};
    strcpy (LogLevel, msg);
    strtok_r (LogLevel, ",",&LogMsg);

    if( strcmp(LogLevel, "RDK_LOG_ERROR") == 0)   
    {
        CcspTraceError((LogMsg));
    }
    else if( strcmp(LogLevel, "RDK_LOG_WARN") == 0)
    {
        CcspTraceWarning((LogMsg));
    }
    else if( strcmp(LogLevel, "RDK_LOG_NOTICE") == 0)
    {
        CcspTraceNotice((LogMsg));
    }
    else if( strcmp(LogLevel, "RDK_LOG_INFO") == 0)
    {
        CcspTraceInfo((LogMsg));
    }
    else if( strcmp(LogLevel, "RDK_LOG_DEBUG") == 0)
    {
        CcspTraceDebug((LogMsg));
    }
    else if( strcmp(LogLevel, "RDK_LOG_FATAL") == 0)
    {
        CcspTraceCritical((LogMsg));
    }
    else
    {
        CcspTraceInfo((LogMsg));
    }
}

/*----------------------------------------------------------------------------*/
/*                             Internal functions                             */
/*----------------------------------------------------------------------------*/

#if defined(_ANSC_LINUX)

/**
 * @brief daemonize is a continous loop running in the background waiting to cater component requests.
 */
static void daemonize(void) {
	
	switch (fork()) {
	case 0:
		break;
	case -1:
		// Error
		CcspTraceInfo(("Harvester: Error daemonizing (fork)! %d - %s\n", errno, strerror(
				errno)));
		exit(0);
		break;
	default:
		_exit(0);
	}

	if (setsid() < 	0) {
		CcspTraceInfo(("Harvester: Error demonizing (setsid)! %d - %s\n", errno, strerror(errno)));
		exit(0);
	}


#ifndef  _DEBUG

	fd = open("/dev/null", O_RDONLY);
	if (fd != 0) {
		dup2(fd, 0);
		close(fd);
	}
	fd = open("/dev/null", O_WRONLY);
	if (fd != 1) {
		dup2(fd, 1);
		close(fd);
	}
	fd = open("/dev/null", O_WRONLY);
	if (fd != 2) {
		dup2(fd, 2);
		close(fd);
	}
#endif
}

#endif


