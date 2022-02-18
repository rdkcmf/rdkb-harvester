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

#ifndef  _CCSP_HARVLOG_WRPPER_H_ 
#define  _CCSP_HARVLOG_WRPPER_H_

extern int consoleDebugEnable;
extern FILE* debugLogFile;

/*
 * Logging wrapper APIs g_Subsystem
 */

#ifdef FEATURE_SUPPORT_RDKLOG
#define WRITELOG HarvesterLog(pTempChar1);
#else
#define WRITELOG Ccsplog3("com.cisco.spvtg.ccsp.harvester", (pTempChar1));
#endif

#define  CcspTraceBaseStr(arg ...)                                                                  \
            do {                                                                                    \
                if (snprintf(pTempChar1, 4095, arg) > (int)sizeof(pTempChar1)) {                    \
                    if(consoleDebugEnable) fprintf(debugLogFile, "%s: truncation while copying arg to pTempChar1 \n", __FUNCTION__);  \
                }                                                                                   \
            } while (FALSE)


#define  CcspHarvesterConsoleTrace(msg)                                                             \
{\
                char* pTempChar1 = (char*)malloc(4096);                                             \
                if ( pTempChar1 )                                                                   \
                {                                                                                   \
                    CcspTraceBaseStr msg;                                                           \
                    if(consoleDebugEnable)                                                          \
                    {\
                        fprintf(debugLogFile, "%s:%d: ", __FILE__, __LINE__);                       \
                        fprintf(debugLogFile, "%s", pTempChar1);                                    \
                        fflush(debugLogFile);                                                       \
                    }\
                    free(pTempChar1);                                                               \
                }\
}

#define  CcspHarvesterTrace(msg)                                                                    \
{\
                char* pTempChar1 = (char*)malloc(4096);                                             \
                if ( pTempChar1 )                                                                   \
                {                                                                                   \
                    CcspTraceBaseStr msg;                                                           \
                    if(consoleDebugEnable)                                                          \
                    {\
                        fprintf(debugLogFile, "%s:%d: ", __FILE__, __LINE__); \
                        fprintf(debugLogFile, "%s", pTempChar1);                                    \
                        fflush(debugLogFile);                                                       \
                    }\
                    WRITELOG  \
                    free(pTempChar1);                                                               \
                }\
}

#define  CcspHarvesterEventTrace(msg)                                                               \
{\
                char* pTempChar1 = (char*)malloc(4096);                                             \
                if ( pTempChar1 )                                                                   \
                {                                                                                   \
                    CcspTraceBaseStr msg;                                                           \
                    if(consoleDebugEnable)                                                          \
                    {\
                        fprintf(debugLogFile, "%s:%d: ", __FILE__, __LINE__); \
                        fprintf(debugLogFile, "%s", pTempChar1);                                    \
                        fflush(debugLogFile);                                                       \
                    }\
                    WRITELOG  \
                    free(pTempChar1);                                                               \
                }                                                                                   \
}

void HarvesterLog(char *);
#endif
