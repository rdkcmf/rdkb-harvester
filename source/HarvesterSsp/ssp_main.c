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
#include "ccsp_harvesterLog_wrapper.h"
#include "safec_lib_common.h"
#include "secure_wrapper.h"
#ifdef RDK_ONEWIFI
#include "harvester_rbus_api.h"
#endif

#ifdef INCLUDE_BREAKPAD
#include "breakpad_wrapper.h"
#endif

#define LOG_LEVEL_MAX 4096

#define NUM_OF_HARVESTER_LOG_TYPES (sizeof(harvester_loglevel_type_table)/sizeof(harvester_loglevel_type_table[0]))

enum har_log_level_type_e {
    LOGERROR,
    LOGWARN,
    LOGNOTICE,
    LOGINFO,
    LOGDEBUG,
    LOGFATAL
};

typedef struct {
  char     *name;
  enum har_log_level_type_e   type;
} HARVESTER_LOG_LEVEL_TYPE;

HARVESTER_LOG_LEVEL_TYPE harvester_loglevel_type_table[] = {
    { "RDK_LOG_ERROR",	LOGERROR },
    { "RDK_LOG_WARN",	LOGWARN },
    { "RDK_LOG_NOTICE", LOGNOTICE },
    { "RDK_LOG_INFO",	LOGINFO },
    { "RDK_LOG_DEBUG",	LOGDEBUG },
    { "RDK_LOG_FATAL",	LOGFATAL }
};



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

int harvester_loglevel_type_from_name(char *name, enum har_log_level_type_e *type_ptr)
{
  int rc = -1;
  int ind = -1;
  int i = 0;
  size_t strsize = 0;
  if((name == NULL) || (type_ptr == NULL))
     return 0;

  strsize = strlen(name);

  for (i = 0 ; i < NUM_OF_HARVESTER_LOG_TYPES ; ++i)
  {
      rc = strcmp_s(name, strsize, harvester_loglevel_type_table[i].name, &ind);
      ERR_CHK(rc);
      if((rc == EOK) && (!ind))
      {
          *type_ptr = harvester_loglevel_type_table[i].type;
          return 1;
      }
  }
  return 0;
}

/**
 * @brief This functionality helps in approaching the bus deamon to create and engage the components.
 */
int  cmd_dispatch(int  command)
{
    ANSC_STATUS  returnStatus        = ANSC_STATUS_SUCCESS;
    switch ( command )
    {
        case    'e' :

#ifdef _ANSC_LINUX
            CcspTraceInfo(("Connect to bus daemon...\n"));

            {
                char                            CName[256];
                errno_t                         rc = -1;


                rc = sprintf_s(CName,sizeof(CName), "%s%s", g_Subsystem, CCSP_COMPONENT_ID);
                if(rc < EOK)
                {
                   ERR_CHK(rc);
                   return -1;
                }

                returnStatus = ssp_Mbi_MessageBusEngage
                    ( 
                        CName,
                        CCSP_MSG_BUS_CFG,
                        CCSP_COMPONENT_PATH
                    );
                if(ANSC_STATUS_SUCCESS != returnStatus)
                   return -1;
				
            }
#endif
         #ifdef RDK_ONEWIFI
             if(harvesterRbusInit(RBUS_HARVESTER_COMPONENT_NAME))
             {
                 fprintf(stderr, "RDK_LOG_ERROR, Harvester component '%s' with RBUS Failed ..\n", RBUS_HARVESTER_COMPONENT_NAME);
             }
             else
             {
                 fprintf(stderr, "RDK_LOG_INFO, Registered Harvester component '%s' with RBUS ..\n", RBUS_HARVESTER_COMPONENT_NAME);
             }
        #endif

            returnStatus = ssp_create();
            if(ANSC_STATUS_SUCCESS != returnStatus)
              return -1;

            returnStatus = ssp_engage();
            if(ANSC_STATUS_SUCCESS != returnStatus)
              return -1;

            break;

        case    'm':

                AnscPrintComponentMemoryTable(pComponentName);

                break;

        case    't':

                AnscTraceMemoryTable();

                break;

        case    'c':
                
               returnStatus = ssp_cancel();
               if(ANSC_STATUS_SUCCESS != returnStatus)
                  return -1;

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
#if 0
    int                             cmdChar            = 0;
#endif
	
    extern ANSC_HANDLE bus_handle;
    char *subSys            = NULL;  
    DmErr_t    err;
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    int                retc = -1;
    errno_t           rc = -1;
	
    rc = strcpy_s(g_Subsystem, sizeof(g_Subsystem), "eRT.");
    if(rc != EOK)
    {
      ERR_CHK(rc);
      CcspTraceError(("exit ERROR %s:%d\n", __FUNCTION__, __LINE__));
      exit(1);
    }

    pComponentName = (char*)name;
    if ( bRunAsDaemon ) 
        daemonize();

#ifdef INCLUDE_BREAKPAD
    breakpad_ExceptionHandler();
#endif /* * INCLUDE_BREAKPAD */

    retc = cmd_dispatch('e');
    if(retc != 0)
    {
      CcspTraceError(("exit ERROR %s:%d\n", __FUNCTION__, __LINE__));
      exit(1);
    }

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
    
    v_secure_system("touch /tmp/harvester_initialized");
    printf("Inside msgBusInit : /tmp/harvester_initialized created\n");
    CcspTraceInfo(("RDK_LOG_WARN, HARV : /tmp/harvester_initialized created\n"));
    CcspHarvesterTrace(("RDK_LOG_WARN,  HARV : /tmp/harvester_initialized created\n"));
    if ( bRunAsDaemon )
    {
        return 1; //Failure
    }
/* CID: 61738 Logically dead code - bRunAsDaemon always TRUE*/
#if 0
    else
    {
        while ( cmdChar != 'q' )
        {
            cmdChar = getchar();

           retc = cmd_dispatch(cmdChar);
           if(retc != 0)
           {
             CcspTraceError(("exit ERROR %s:%d\n", __FUNCTION__, __LINE__));
             exit(1);
           }
        }
    }
#endif
    err = Cdm_Term();
    if (err != CCSP_SUCCESS)
    {
    fprintf(stderr, "Cdm_Term: %s\n", Cdm_StrError(err));
    exit(1);
    }

    returnStatus = ssp_cancel();
    if(ANSC_STATUS_SUCCESS != returnStatus)
    {
       CcspTraceError(("exit ERROR %s:%d\n", __FUNCTION__, __LINE__));
       exit(1);
    }

	
    return 0; //Success
}

void HarvesterLog(char *msg)
{
    char LogMsg_arr[4096] = {0};
    char *LogMsg = LogMsg_arr;
    char LogLevel[4096] = {0};
    char *tok = NULL;
    size_t len = 0;
    errno_t rc = -1;
    enum har_log_level_type_e type;

    if(msg[0] == '\0')
      return;
  
    /* Coverity Fix CID: 135571 STRING_OVERFLOW */
    if(strlen(msg) < LOG_LEVEL_MAX)
    {
      rc = strcpy_s(LogLevel, sizeof(LogLevel), msg);
      if(rc != EOK)
      {
        ERR_CHK(rc);
        return;
      }
    }

    len = strlen(LogLevel);
    tok = strtok_s (LogLevel, &len, ",", &LogMsg);

    if (LogMsg[0] != '\0')
    {
      if (harvester_loglevel_type_from_name(LogLevel, &type))
      {
        if(type == LOGERROR)
        {
          CcspTraceError(("%s\n", LogMsg));
        }
        else if(type == LOGWARN)
        {
          CcspTraceWarning(("%s\n", LogMsg));
        }
        else if(type == LOGNOTICE)
        {
          CcspTraceNotice(("%s\n", LogMsg));
        }
        else if(type == LOGINFO)
        {
          CcspTraceInfo(("%s\n", LogMsg));
        }
        else if(type == LOGDEBUG )
        {
          CcspTraceDebug(("%s\n", LogMsg));
        }
        else if(type == LOGFATAL )
        {
          CcspTraceCritical(("%s\n", LogMsg));
        }
      }
      else
      {
        CcspTraceInfo(("%s\n", LogMsg));
      }  
    }
    // tok is unused
    (void)(tok);	
    (void)(len);
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


