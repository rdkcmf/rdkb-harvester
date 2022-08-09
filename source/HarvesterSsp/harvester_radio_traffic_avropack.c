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
#include <assert.h>
#include <avro.h>
#include <arpa/inet.h>
#include <semaphore.h>  /* Semaphore */
#include <uuid/uuid.h>

#include "ansc_platform.h"

#include "base64.h"
#include "harvester.h"
#include "harvester_avro.h"
#include "ccsp_harvesterLog_wrapper.h"
#include "safec_lib_common.h"
#ifdef RDK_ONEWIFI
#include "harvester_rbus_api.h"
#endif


#define MAGIC_NUMBER      0x85
#define MAGIC_NUMBER_SIZE 1
#define SCHEMA_ID_LENGTH  32
#define WRITER_BUF_SIZE  (1024 * 30) // 30K

#define NUM_OF_RADIO_OPERATING_CHANNEL_BANDWIDTHS (sizeof(radio_operating_channel_bandwidth_table)/sizeof(radio_operating_channel_bandwidth_table[0]))

// HASH - 44b72f483a79e851ad61073dd5373535
// UUID - 4d1f3d40-ab59-4672-89e6-c8cfdca739a0

uint8_t RT_HASH[16] = {0x44, 0xb7, 0x2f, 0x48, 0x3a, 0x79, 0xe8, 0x51,
                       0xad, 0x61, 0x07, 0x3d, 0xd5, 0x37, 0x35, 0x35
                        };

uint8_t RT_UUID[16] = {0x4d, 0x1f, 0x3d, 0x40, 0xab, 0x59, 0x46, 0x72,
                       0x89, 0xe6, 0xc8, 0xcf, 0xdc, 0xa7, 0x39, 0xa0
                        };

/**** temperatory raw data ****/

static char ReportSource[] = "harvester";
static char CPE_TYPE_STRING[] = "Gateway";
static char PARENT_CPE_TYPE_STRING[] = "Extender";
static char ParentCpeMacid[] = { 0x77, 0x88, 0x99, 0x00, 0x11, 0x22 };
static int cpe_parent_exists = FALSE;
//static char ServiceType[] = "PRIVATE";

/**** temperatory raw data ****/

#if !defined(UTC_ENABLE_ATOM) && !defined(_HUB4_PRODUCT_REQ_)
extern int getTimeOffsetFromUtc();
#endif
extern ULONG GetRTReportingInterval();
extern ULONG GetRTPollingInterval();

static char *macStr = NULL;
static char CpemacStr[ 32 ];

char *ris_schemaidbuffer = "4d1f3d40-ab59-4672-89e6-c8cfdca739a0/44b72f483a79e851ad61073dd5373535";
static   avro_value_iface_t  *iface = NULL;
char *rt_schema_buffer;
BOOL rt_schema_file_parsed = FALSE;
static size_t AvroRTSerializedSize;
static size_t OneAvroRTSerializedSize;
char AvroRTSerializedBuf[WRITER_BUF_SIZE];


enum channel_bandwidth_e {
    MHZ20,
    MHZ40,
    MHZ80,
    MHZ80_80,
    MHZ160,
};

typedef struct {
  char     *name;
  enum channel_bandwidth_e  type;
} RADIO_OPERATING_CHANNEL_BANDWIDTH;

RADIO_OPERATING_CHANNEL_BANDWIDTH radio_operating_channel_bandwidth_table[] = {
    { "20MHz",MHZ20 },
    { "40MHz",MHZ40 },
    { "80MHz", MHZ80 },
    { "80_80MHz",MHZ80_80 },
    { "160MHz",	MHZ160 }
};

int get_radiOperatingChannelBandwidth_from_name(char *name, enum channel_bandwidth_e *type_ptr)
{
  int rc = -1;
  int ind = -1;
  int i = 0;
  size_t strsize = 0;
  if((name == NULL) || (type_ptr == NULL))
     return 0;

  strsize = strlen(name);

  for (i = 0 ; i < NUM_OF_RADIO_OPERATING_CHANNEL_BANDWIDTHS ; ++i)
  {
      rc = strcmp_s(name, strsize, radio_operating_channel_bandwidth_table[i].name, &ind);
      ERR_CHK(rc);
      if((rc == EOK) && (!ind))
      {
          *type_ptr = radio_operating_channel_bandwidth_table[i].type;
          return 1;
      }
  }
  return 0;
}


char* GetRISSchemaBuffer()
{
  return rt_schema_buffer;
}

int GetRISSchemaBufferSize()
{
int len = 0;
if(rt_schema_buffer)
  len = strlen(rt_schema_buffer);
  
return len;
}

char* GetRISSchemaIDBuffer()
{
  return ris_schemaidbuffer;
}

int GetRISSchemaIDBufferSize()
{
int len = 0;
if(ris_schemaidbuffer)
        len = strlen(ris_schemaidbuffer);

return len;
}

#if 0
int NumberofRTElementsinLinkedList(struct radiotrafficdata* head)
{
  int numelements = 0;
  struct radiotrafficdata* ptr  = head;
  while (ptr != NULL)
  {
    numelements++;
    ptr = ptr->next;
  }
  return numelements;
}
#endif

avro_writer_t prepare_rt_writer()
{
  avro_writer_t writer ={0};
  long lsSize = 0;
  errno_t rc = -1;

  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));

  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Avro prepares to serialize data\n"));

  if ( rt_schema_file_parsed == FALSE )
  {
    FILE *fp;

    /* open schema file */
    fp = fopen ( RADIO_INTERFACE_STATS_AVRO_FILENAME , "rb" );
    if ( !fp ) perror( RADIO_INTERFACE_STATS_AVRO_FILENAME " doesn't exist."), exit(1);

    /* seek through file and get file size*/
    fseek( fp , 0L , SEEK_END);
    lsSize = ftell( fp );

       /* Coverity Fix CID: 72156  NEGATIVE RETURN */
    if(lsSize < 0)
    {
        fputs("lsSize attain Negative Value", stderr);
        fclose(fp);
         return writer;
    }
 

    /*back to the start of the file*/
    rewind( fp );

    /* allocate memory for entire content */
    rt_schema_buffer = calloc( 1, lsSize + 1 );

    if ( !rt_schema_buffer ) fclose(fp), fputs("memory alloc fails", stderr), exit(1);

    /* copy the file into the RT_schema_buffer */
    if ( 1 != fread( rt_schema_buffer , lsSize, 1 , fp) )
      fclose(fp), free(rt_schema_buffer), fputs("entire read fails", stderr), exit(1);

    fclose(fp);

    /* CID: 135349 String not null terminated*/
    rt_schema_buffer[lsSize] = '\0';

    //schemas
    avro_schema_error_t  error = NULL;

    //Master report/datum
    avro_schema_t radiotraffic_device_report_schema = NULL;
    

    avro_schema_from_json(rt_schema_buffer, strlen(rt_schema_buffer),
                        &radiotraffic_device_report_schema, &error);

    //generate an avro class from our schema and get a pointer to the value interface
    iface = avro_generic_class_from_schema(radiotraffic_device_report_schema);
    avro_schema_decref(radiotraffic_device_report_schema);
    rt_schema_file_parsed = TRUE; // parse schema file once only
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Read Avro schema file ONCE, lsSize = %ld, RT_schema_buffer = 0x%lx.\n", lsSize + 1, (ulong)rt_schema_buffer ));
  }
  else
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Stored lsSize = %ld, pRT_schema_buffer = 0x%lx.\n", lsSize + 1, (ulong)rt_schema_buffer ));

  rc = memset_s(&AvroRTSerializedBuf[0], sizeof(AvroRTSerializedBuf), 0, sizeof(AvroRTSerializedBuf));
  ERR_CHK(rc);

  AvroRTSerializedBuf[0] = MAGIC_NUMBER; /* fill MAGIC number */
  rc = memcpy_s(&AvroRTSerializedBuf[ MAGIC_NUMBER_SIZE ], sizeof(AvroRTSerializedBuf)-MAGIC_NUMBER_SIZE, RT_UUID, sizeof(RT_UUID));
  if(rc != EOK)
  {
    ERR_CHK(rc);
    return writer;
  }
  rc = memcpy_s(&AvroRTSerializedBuf[ MAGIC_NUMBER_SIZE + sizeof(RT_UUID) ], sizeof(AvroRTSerializedBuf)-MAGIC_NUMBER_SIZE-sizeof(RT_UUID), RT_HASH, sizeof(RT_HASH));
  if(rc != EOK)
  {
    ERR_CHK(rc);
    return writer;
  }
  writer = avro_writer_memory( (char*)&AvroRTSerializedBuf[MAGIC_NUMBER_SIZE + SCHEMA_ID_LENGTH],
                               sizeof(AvroRTSerializedBuf) - MAGIC_NUMBER_SIZE - SCHEMA_ID_LENGTH );

  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

  return writer;
}


/* function call from harvester with parameters */
void harvester_report_radiotraffic(struct radiotrafficdata *ptr)
{
  int k = 0, i = 0;
  uint8_t* b64buffer =  NULL;
  size_t decodesize = 0;
  ULONG numElements = 0;
  wifi_radioTrafficStats2_t *ps = NULL;
  avro_writer_t writer;
  char * serviceName = "harvester";
  char * dest = "event:raw.kestrel.reports.RadioInterfacesStatistics";
  char * contentType = "avro/binary"; // contentType "application/json", "avro/binary"
  uuid_t transaction_id;
  char trans_id[37];
  size_t strsize2_4GHZ = 0;
  size_t strsize5GHZ = 0;
#ifdef WIFI_HAL_VERSION_3
  size_t strsize6GHZ = 0;
#endif
  int rc = -1;
  int ind = -1;
  enum channel_bandwidth_e  type;

  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));


  OneAvroRTSerializedSize = 0;

  // goes thru total number of elements in link list 
  writer = prepare_rt_writer();

 
  //Reset out writer
  avro_writer_reset(writer);

  //neighborAp Device Report
  avro_value_t  adr = {0}; /*RDKB-7466, CID-33408, init before use */
  avro_generic_value_new(iface, &adr);
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, GatewayWifiRadioReport\tType: %d\n", avro_value_get_type(&adr)));

  avro_value_t  adrField= {0}; /*RDKB-7466, CID-33157, init before use */

  //Optional value for unions, mac address is an union
  avro_value_t optional= {0}; /*RDKB-7466, CID-33203, init before use */

  // timestamp - long
  avro_value_get_by_name(&adr, "header", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_get_by_name(&adrField, "timestamp", &adrField, NULL);
  avro_value_set_branch(&adrField, 1, &optional);
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  struct timeval ts;
  gettimeofday(&ts, NULL);
#if !defined(UTC_ENABLE_ATOM) && !defined(_HUB4_PRODUCT_REQ_)  
  int64_t tstamp_av_main = ((int64_t) (ts.tv_sec - getTimeOffsetFromUtc()) * 1000000) + (int64_t) ts.tv_usec;
#else
  int64_t tstamp_av_main = ((int64_t) (ts.tv_sec) * 1000000) + (int64_t) ts.tv_usec;
#endif
  tstamp_av_main = tstamp_av_main/1000;

  avro_value_set_long(&optional, tstamp_av_main );
   /* Coverity Fix CID: 125074  PRINTF_ARGS */
#ifdef _64BIT_ARCH_SUPPORT_
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, timestamp = %ld\n", tstamp_av_main ));
#else
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, timestamp = %lld\n", tstamp_av_main ));
#endif
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, timestamp\tType: %d\n", avro_value_get_type(&optional)));
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  // uuid - fixed 16 bytes
  uuid_generate_random(transaction_id); 
  uuid_unparse(transaction_id, trans_id);

  avro_value_get_by_name(&adr, "header", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_get_by_name(&adrField, "uuid", &adrField, NULL);
  avro_value_set_branch(&adrField, 1, &optional);
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_set_fixed(&optional, transaction_id, 16);
  unsigned char *ptxn = (unsigned char*)transaction_id;
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, uuid = 0x%02X, 0x%02X ... 0x%02X, 0x%02X\n", ptxn[0], ptxn[1], ptxn[14], ptxn[15] ));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, uuid\tType: %d\n", avro_value_get_type(&optional)));
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  //source - string
  avro_value_get_by_name(&adr, "header", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_get_by_name(&adrField, "source", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_set_branch(&adrField, 1, &optional);
  avro_value_set_string(&optional, ReportSource);
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, source = \"%s\"\n", ReportSource ));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, source\tType: %d\n", avro_value_get_type(&optional)));
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  //cpe_id block
  /* MAC - Get CPE mac address, do it only pointer is NULL */
  if ( macStr == NULL )
  {
    macStr = getDeviceMac();

    rc = strcpy_s(CpemacStr,sizeof(CpemacStr),macStr);
    if(rc != EOK)
    {
       ERR_CHK(rc);
       return;
    }
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Received DeviceMac from Atom side: %s\n",macStr));
  }

  char CpeMacHoldingBuf[ 20 ] = {0};
  unsigned char CpeMacid[ 7 ] = {0};
  for (k = 0; k < 6; k++ )
  {
    /* copy 2 bytes */
    CpeMacHoldingBuf[ k * 2 ] = CpemacStr[ k * 2 ];
    CpeMacHoldingBuf[ k * 2 + 1 ] = CpemacStr[ k * 2 + 1 ];
    CpeMacid[ k ] = (unsigned char)strtol(&CpeMacHoldingBuf[ k * 2 ], NULL, 16);
  }
  avro_value_get_by_name(&adr, "cpe_id", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_get_by_name(&adrField, "mac_address", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_set_branch(&adrField, 1, &optional);
  avro_value_set_fixed(&optional, CpeMacid, 6);
  unsigned char *pMac = (unsigned char*)CpeMacid;
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, mac_address = 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n", pMac[0], pMac[1], pMac[2], pMac[3], pMac[4], pMac[5] ));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, mac_address\tType: %d\n", avro_value_get_type(&optional)));
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  // cpe_type - string
  avro_value_get_by_name(&adr, "cpe_id", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_get_by_name(&adrField, "cpe_type", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_set_branch(&adrField, 1, &optional);
  avro_value_set_string(&optional, CPE_TYPE_STRING);
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, cpe_type = \"%s\"\n", CPE_TYPE_STRING ));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, cpe_type\tType: %d\n", avro_value_get_type(&optional)));
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  // cpe_parent - Recurrsive CPEIdentifier block
  avro_value_get_by_name(&adr, "cpe_id", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  avro_value_get_by_name(&adrField, "cpe_parent", &adrField, NULL);
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  if ( cpe_parent_exists == FALSE )
  {
      avro_value_set_branch(&adrField, 0, &optional);
      avro_value_set_null(&optional);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, cpe_parent = %s\n", "NULL" ));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, cpe_parent\tType: %d\n", avro_value_get_type(&optional)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  }
  else
  {
      avro_value_t parent_optional, parent_adrField;

      // assume 1 parent ONLY
      // Parent MAC
      avro_value_set_branch(&adrField, 1, &parent_optional);
      avro_value_get_by_name(&parent_optional, "mac_address", &parent_adrField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&parent_adrField, 1, &parent_optional);
      avro_value_set_fixed(&parent_optional, ParentCpeMacid, 6);
      unsigned char *pMac = (unsigned char*)ParentCpeMacid;
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, parent mac = 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n", pMac[0], pMac[1], pMac[2], pMac[3], pMac[4], pMac[5] ));
     CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, parent mac_address\tType: %d\n", avro_value_get_type(&parent_optional)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      // Parent cpe_type
      avro_value_set_branch(&adrField, 1, &parent_optional);
      avro_value_get_by_name(&parent_optional, "cpe_type", &parent_adrField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&parent_adrField, 1, &parent_optional);
      avro_value_set_string(&parent_optional, PARENT_CPE_TYPE_STRING);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, parent cpe_type = \"%s\"\n", PARENT_CPE_TYPE_STRING ));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, parent cpe_type\tType: %d\n", avro_value_get_type(&parent_optional)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      // no more parent, set NULL
      avro_value_set_branch(&adrField, 1, &parent_optional);
      avro_value_get_by_name(&parent_optional, "cpe_parent", &parent_adrField, NULL);
      avro_value_set_branch(&parent_adrField, 0, &parent_optional);
      avro_value_set_null(&parent_optional);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, parent cpe_parent = %s\n", "NULL" ));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, parent cpe_parent\tType: %d\n", avro_value_get_type(&parent_optional)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
  }

  //Data Field block

  avro_value_get_by_name(&adr, "data", &adrField, NULL);
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Radio Traffic Reports - data array\tType: %d\n", avro_value_get_type(&adrField)));
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  //adrField now contains a reference to the AssociatedDeviceReportsArray
  //Device Report
  avro_value_t dr= {0}; /*RDKB-7466, CID-33127, init before use */

  //Current Device Report Field
  avro_value_t drField= {0}; /*RDKB-7466, CID-33408, init before use */
  
  strsize2_4GHZ = strlen("2.4GHz");
  strsize5GHZ = strlen("5GHz");
#ifdef WIFI_HAL_VERSION_3
  strsize6GHZ = strlen("6GHz");
#endif

    #ifdef RDK_ONEWIFI
           rc = rbus_getUInt32Value(&numElements, "Device.WiFi.RadioNumberOfEntries");
    #else
           rc = wifi_getRadioNumberOfEntries(&numElements);
    #endif
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, wifi_getRadioNumberOfEntries() ret value %d\n", rc));
    if(rc != EOK)
    {
       ERR_CHK(rc);
       return;
    }

    for(i = 0; i < numElements; i++)
    {
      if(ptr == NULL)
      {
          ptr++;
          CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : struct ptr for index[%d] is NULL\n", __FUNCTION__, i ));
          continue;
      }
      else
      {
          if(ptr->radioBssid == NULL || ptr->radioOperatingFrequencyBand == NULL || ptr->radiOperatingChannelBandwidth == NULL || ptr->rtdata == NULL)
          {
              ptr++;
              CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s : index[%d] struct has some or whole parameters were NULL\n", __FUNCTION__, i ));
              continue;
          }
          CcspHarvesterTrace(("RDK_LOG_DEBUG, Harvester %s : index[%d] NULL checks are Success\n", __FUNCTION__, i));
      }

      ps = ptr->rtdata;
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, numElements = %ld\n", numElements ));

      //Append a Radio Report item to array
      avro_value_append(&adrField, &dr, NULL);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, WifiRadioReport\tType: %d\n", avro_value_get_type(&dr)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //report_header block

      //radio_mac
      avro_value_get_by_name(&dr, "radio_mac", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //radio_bssid - fixed
      char bssidShortened[ 20 ] = {0};
      unsigned char bssid[ 6 ] = {0};
      int number = 0;
      for (k = 0; k < 6; k++ )
      {
        /* skip the : */
        bssidShortened[ k * 2 ] = ptr->radioBssid[ k * 2 + number ];
        bssidShortened[ k * 2 + 1 ] = ptr->radioBssid[ k * 2 + number + 1 ];
        bssid[ k ] = (int)strtol(&bssidShortened[ k * 2 ], NULL, 16);
        number++;
      }
      pMac = (unsigned char*)bssid;
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, radio_mac address = 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n", pMac[0], pMac[1], pMac[2], pMac[3], pMac[4], pMac[5] ));
      avro_value_set_fixed(&drField, bssid, 6);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, radio_mac\tType: %d\n", avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //timestamp - long
      avro_value_get_by_name(&dr, "timestamp", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      int64_t tstamp_av = (int64_t) ptr->timestamp.tv_sec * 1000000 + (int64_t) ptr->timestamp.tv_usec;
      tstamp_av = tstamp_av/1000;
      avro_value_set_long(&optional, tstamp_av);
       /* Coverity Fix CID: 124885  PRINTF_ARGS*/
#ifdef _64BIT_ARCH_SUPPORT_
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, timestamp = %ld\n", tstamp_av));
#else
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, timestamp = %lld\n", tstamp_av));
#endif
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, timestamp\tType: %d\n", avro_value_get_type(&optional)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //radio_enabled
      avro_value_get_by_name(&dr, "enabled", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, enabled\tType: %d\n", avro_value_get_type(&optional)));
      if ( ptr->enabled )
      {
          CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, enabled = TRUE\n"));
          avro_value_set_boolean(&drField, TRUE);
      }
      else
      {
          CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, enabled = FALSE\n"));
          avro_value_set_boolean(&drField, FALSE);
      }

      //radio_channel
      avro_value_get_by_name(&dr, "channel", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_int(&optional, ptr->radioChannel);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, channel = %ld\n", ptr->radioChannel));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, channel\tType: %d\n",avro_value_get_type(&optional)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      // frequency band
      avro_value_get_by_name(&dr, "frequency_band", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, frequency_band\tType: %d\n", avro_value_get_type(&optional)));
      //Patch HAL values if necessary
      rc = strcmp_s("2.4GHz", strsize2_4GHZ, ptr->radioOperatingFrequencyBand, &ind);
      ERR_CHK(rc);
      if((rc == EOK) && (!ind))
      {
         CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, frequency_band = \"%s\"\n", "2.4GHz, set to _2_4GHz" ));
         avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_2_4GHz" ));
      }
      else
      {
         rc = strcmp_s("5GHz", strsize5GHZ, ptr->radioOperatingFrequencyBand, &ind);
         ERR_CHK(rc);
         if((rc == EOK) && (!ind))
         {
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, frequency_band = \"%s\"\n", "5GHz, set to _5GHz" ));
            avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_5GHz" ));
         }
#ifndef WIFI_HAL_VERSION_3
         else
         {
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, frequency_band = \"%s\"\n", ptr->radioOperatingFrequencyBand ));
            avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), ptr->radioOperatingFrequencyBand));
         }
#else
         else
         {
            rc = strcmp_s("6GHz", strsize6GHZ, ptr->radioOperatingFrequencyBand, &ind);
            ERR_CHK(rc);
            if((rc == EOK) && (!ind))
            {
               CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, frequency_band = \"%s\"\n", "6GHz, set to _6GHz" ));
               avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_6GHz" ));
            }
            else
            {
               CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, frequency_band = \"%s\"\n", ptr->radioOperatingFrequencyBand ));
               avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), ptr->radioOperatingFrequencyBand));
            }
         }
#endif
      }

      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      // operating channel bandwidth
      avro_value_get_by_name(&dr, "operating_channel_bandwidth", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, operating_channel_bandwidth\tType: %d\n", avro_value_get_type(&optional)));
      //Patch
      if(get_radiOperatingChannelBandwidth_from_name(ptr->radiOperatingChannelBandwidth, &type))
      {
         if(type == MHZ20)
         {
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, operating_channel_bandwidth = \"%s\"\n", "20MHz, set to _20MHz" ));
            avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_20MHz"));	 
         }
         else if(type == MHZ40)
         {
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, operating_channel_bandwidth = \"%s\"\n", "40MHz, set to _40MHz" )); 		 avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_40MHz"));
         }
         else if(type == MHZ80)
         {
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, operating_channel_bandwidth = \"%s\"\n", "80MHz, set to _80MHz" )); 		 avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_80MHz"));
         }
         else if(type == MHZ80_80)
         {
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, operating_channel_bandwidth = \"%s\"\n", "80_80MHz, set to _80_80MHz" ));
            avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_80_80MHz"));
         }
         else if(type == MHZ160)
         {
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, operating_channel_bandwidth = \"%s\"\n", "160MHz, set to _160MHz" ));
            avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_160MHz"));
         }
      }
      else
      {
         CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, operating_channel_bandwidth = %s\n", ptr->radiOperatingChannelBandwidth ));			avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), ptr->radiOperatingChannelBandwidth));
      }

      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //radio_noise_floor
      avro_value_get_by_name(&dr, "noise_floor", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, noise_floor = %d\n", ps->radio_NoiseFloor ));                     
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, noise_floor\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_float(&optional, (float)ps->radio_NoiseFloor);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //radio_ChannelUtilization
      avro_value_get_by_name(&dr, "channel_utilization", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, channel_utilization = %ld\n", ps->radio_ChannelUtilization ));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, channel_utilization\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_float(&optional, (float)ps->radio_ChannelUtilization);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //radio_activity_factor
      avro_value_get_by_name(&dr, "activity_factor", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, activity_factor = %d\n", ps->radio_ActivityFactor));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, activity_factor\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_float(&optional, (float)ps->radio_ActivityFactor);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //radio_carrier_sense_threshold_exceeded
      avro_value_get_by_name(&dr, "carrier_sense_threshold_exceeded", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, carrier_sense_threshold_exceeded = %d\n", ps->radio_CarrierSenseThreshold_Exceeded));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, carrier_sense_threshold_exceeded\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_float(&optional, (float)ps->radio_CarrierSenseThreshold_Exceeded);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //radio_retransmission_metric
      avro_value_get_by_name(&dr, "retransmission_metric", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, retransmission_metric = %d\n", ps->radio_RetransmissionMetirc));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, retransmission_metric\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_float(&optional, (float)ps->radio_RetransmissionMetirc);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //radio_maximum_noise_floor_on_channel
      avro_value_get_by_name(&dr, "maximum_noise_floor_on_channel", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, maximum_noise_floor_on_channel = %d\n", ps->radio_MaximumNoiseFloorOnChannel));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, maximum_noise_floor_on_channel\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_float(&optional, (float)ps->radio_MaximumNoiseFloorOnChannel);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //radio_minimum_noise_floor_on_channel
      avro_value_get_by_name(&dr, "minimum_noise_floor_on_channel", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, minimum_noise_floor_on_channel = %d\n", ps->radio_MinimumNoiseFloorOnChannel));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, minimum_noise_floor_on_channel\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_float(&optional, (float)ps->radio_MinimumNoiseFloorOnChannel);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //radio_median_noise_floor_on_channel
      avro_value_get_by_name(&dr, "median_noise_floor_on_channel", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, minimum_noise_floor_on_channel = %d\n", ps->radio_MedianNoiseFloorOnChannel));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, median_noise_floor_on_channel\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_float(&optional, (float)ps->radio_MedianNoiseFloorOnChannel);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      ptr++;

      /* check for writer size, if buffer is almost full, skip trailing linklist */
      avro_value_sizeof(&adr, &AvroRTSerializedSize);
      OneAvroRTSerializedSize = ( OneAvroRTSerializedSize == 0 ) ? AvroRTSerializedSize : OneAvroRTSerializedSize;

      if ( ( WRITER_BUF_SIZE - AvroRTSerializedSize ) < OneAvroRTSerializedSize )
      {
        CcspHarvesterTrace(("RDK_LOG_ERROR, AVRO write buffer is almost full, size = %d func %s, exit!\n", (int)AvroRTSerializedSize, __FUNCTION__ ));
        break;
      }
  }

  //Thats the end of that
  avro_value_write(writer, &adr);

  avro_value_sizeof(&adr, &AvroRTSerializedSize);
  AvroRTSerializedSize += MAGIC_NUMBER_SIZE + SCHEMA_ID_LENGTH;
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Serialized writer size %d\n", (int)AvroRTSerializedSize));

  //Free up memory
  avro_value_decref(&adr);
  avro_writer_free(writer);
  //free(RT_schema_buffer);

  // b64 encoding
  decodesize = b64_get_encoded_buffer_size( AvroRTSerializedSize );
  b64buffer = malloc(decodesize * sizeof(uint8_t));
  b64_encode( (uint8_t*)AvroRTSerializedBuf, AvroRTSerializedSize, b64buffer);

  if ( consoleDebugEnable )
  {
    fprintf( stderr, "\nAVro serialized data\n");
    for (k = 0; k < (int)AvroRTSerializedSize ; k++)
    {
      char buf[30];
      if ( ( k % 32 ) == 0 )
        fprintf( stderr, "\n");
      rc = sprintf_s(buf,sizeof(buf),"%02X", (unsigned char)AvroRTSerializedBuf[k]);
      if(rc < EOK)
      {
        ERR_CHK(rc);
        free(b64buffer);
        return;
      }
      fprintf( stderr, "%c%c", buf[0], buf[1] );
    }

    fprintf( stderr, "\n\nB64 data\n");
    for (k = 0; k < (int)decodesize; k++)
    {
      if ( ( k % 32 ) == 0 )
        fprintf( stderr, "\n");
      fprintf( stderr, "%c", b64buffer[k]);
    }
    fprintf( stderr, "\n\n");
  }
  
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Before RT WebPA SEND message call\n"));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, serviceName: %s\n", serviceName));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, dest: %s\n", dest));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, trans_id: %s\n", trans_id));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, contentType: %s\n", contentType));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AvroRTSerializedBuf: %s\n", AvroRTSerializedBuf));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AvroRTSerializedSize: %d\n", (int)AvroRTSerializedSize));
  // Send data from Harvester to webpa using CCSP bus interface
  sendWebpaMsg(serviceName, dest, trans_id, contentType, AvroRTSerializedBuf , AvroRTSerializedSize);

  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, After RT WebPA SEND message call\n"));

  free(b64buffer);

  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

#if SIMULATION
  exit(0);
#endif
}

void rt_avro_cleanup()
{
  if(rt_schema_buffer != NULL) {
        free(rt_schema_buffer); 
        rt_schema_buffer=NULL;
  } 
  if(iface != NULL){
        avro_value_iface_decref(iface);
        iface = NULL;
  }
  rt_schema_file_parsed = FALSE;
}


