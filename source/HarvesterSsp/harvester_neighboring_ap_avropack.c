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
#include <uuid/uuid.h>

#include "ansc_platform.h"

#include "base64.h"
#include "harvester.h"
#include "harvester_avro.h"
#include "ccsp_harvesterLog_wrapper.h"
#include "safec_lib_common.h"


#define MAGIC_NUMBER      0x85
#define MAGIC_NUMBER_SIZE 1
#define SCHEMA_ID_LENGTH  32
#define WRITER_BUF_SIZE  (1024 * 150) // 150K

//      "schemaTypeUUID" : "e375b355-988b-45f8-9ec9-feb4b53ed843",
//      "schemaMD5Hash" : "4ae36536e6cbf4e4a0d5d873d0668bfb",

uint8_t NAP_HASH[16] = {0x4a, 0xe3, 0x65, 0x36, 0xe6, 0xcb, 0xf4, 0xe4,
                        0xa0, 0xd5, 0xd8, 0x73, 0xd0, 0x66, 0x8b, 0xfb
                        };

uint8_t NAP_UUID[16] = {0xe3, 0x75, 0xb3, 0x55, 0x98, 0x8b, 0x45, 0xf8,
                        0x9e, 0xc9, 0xfe, 0xb4, 0xb5, 0x3e, 0xd8, 0x43
                        };

pthread_mutex_t avropack_mutex = PTHREAD_MUTEX_INITIALIZER;

extern ULONG GetNAPReportingPeriod();
extern ULONG GetNAPPollingPeriod();

static char *macStr = NULL;
static char CpemacStr[ 32 ];


char *nap_schema_buffer;
char *nap_schemaidbuffer = "e375b355-988b-45f8-9ec9-feb4b53ed843/4ae36536e6cbf4e4a0d5d873d0668bfb";
static   avro_value_iface_t  *iface = NULL;
BOOL nap_schema_file_parsed = FALSE;
size_t AvroNAPSerializedSize;
size_t OneAvroNAPSerializedSize;
char AvroNAPSerializedBuf[WRITER_BUF_SIZE];

char* GetNAPSchemaBuffer()
{
  return nap_schema_buffer;
}

int GetNAPSchemaBufferSize()
{
int len = 0;
if(nap_schema_buffer)
  len = strlen(nap_schema_buffer);
  
return len;
}

char* GetNAPSchemaIDBuffer()
{
  return nap_schemaidbuffer;
}

int GetNAPSchemaIDBufferSize()
{
int len = 0;
if(nap_schemaidbuffer)
        len = strlen(nap_schemaidbuffer);

return len;
}


char* GetNeighborAPAvroBuf()
{
  return AvroNAPSerializedBuf;
}

int GetNeighborAPAvroBufSize()
{
  return AvroNAPSerializedSize;
}

int NumberofNAPElementsinLinkedList(struct neighboringapdata* head)
{
  int numelements = 0;
  struct neighboringapdata* ptr  = head;
  while (ptr != NULL)
  {
    numelements++;
    ptr = ptr->next;
  }
  return numelements;
}


ULONG NumberofNAPDevicesinLinkedList(struct neighboringapdata* head)
{
  ULONG numdevices = 0;
  struct neighboringapdata* ptr  = head;
  while (ptr != NULL)
  {
    numdevices = numdevices + ptr->numNeibouringAP;
    ptr = ptr->next;
  }
  return numdevices;
}

avro_writer_t prepare_nap_writer()
{
  avro_writer_t writer ={0};
  long lsSize = 0;
  errno_t rc = -1;

  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));

  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Avro prepares to serialize data\n"));

  if ( nap_schema_file_parsed == FALSE )
  {
    FILE *fp;

    /* open schema file */
    fp = fopen ( NEIGHBORHOOD_SCAN_AVRO_FILENAME , "rb" );
    if ( !fp ) perror( NEIGHBORHOOD_SCAN_AVRO_FILENAME " doesn't exist."), exit(1);

    /* seek through file and get file size*/
    fseek( fp , 0L , SEEK_END);
    lsSize = ftell( fp );
   
    /* Coverity Fix CID: 70128 NEGATIVE RETURN */
    if(lsSize < 0)
    {
         fputs("lsSize attain Negative Value", stderr);
          fclose(fp);
          return writer;
    }


    /*back to the start of the file*/
    rewind( fp );

    /* allocate memory for entire content */
    nap_schema_buffer = calloc( 1, lsSize + 1 );

    if ( !nap_schema_buffer ) fclose(fp), fputs("memory alloc fails", stderr), exit(1);

    /* copy the file into the nap_schema_buffer */
    if ( 1 != fread( nap_schema_buffer , lsSize, 1 , fp) )
      fclose(fp), free(nap_schema_buffer), fputs("entire read fails", stderr), exit(1);

    fclose(fp);

    /* CID:135280 String not null terminated */
    nap_schema_buffer[lsSize]= '\0';

    //schemas
    avro_schema_error_t  error = NULL;

    //Master report/datum
    avro_schema_t neighborAp_device_report_schema = NULL;
    
    avro_schema_from_json(nap_schema_buffer, strlen(nap_schema_buffer),
                        &neighborAp_device_report_schema, &error);

    //generate an avro class from our schema and get a pointer to the value interface
    iface = avro_generic_class_from_schema(neighborAp_device_report_schema);
    avro_schema_decref(neighborAp_device_report_schema);
    nap_schema_file_parsed = TRUE; // parse schema file once only
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Read Avro schema file ONCE, lsSize = %ld, pnap_schema_buffer = 0x%lx.\n", lsSize + 1, (ulong)nap_schema_buffer ));
  }
  else
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Stored lsSize = %ld, pnap_schema_buffer = 0x%lx.\n", lsSize + 1, (ulong)nap_schema_buffer ));

  rc = memset_s(&AvroNAPSerializedBuf[0], sizeof(AvroNAPSerializedBuf), 0, sizeof(AvroNAPSerializedBuf));
  ERR_CHK(rc);

  AvroNAPSerializedBuf[0] = MAGIC_NUMBER; /* fill MAGIC number */
  rc = memcpy_s(&AvroNAPSerializedBuf[ MAGIC_NUMBER_SIZE ], sizeof(AvroNAPSerializedBuf)-MAGIC_NUMBER_SIZE, NAP_UUID, sizeof(NAP_UUID));
  if(rc != EOK)
  {
    ERR_CHK(rc);
    return writer;
  }
  rc = memcpy_s(&AvroNAPSerializedBuf[ MAGIC_NUMBER_SIZE + sizeof(NAP_UUID) ], sizeof(AvroNAPSerializedBuf)-MAGIC_NUMBER_SIZE-sizeof(NAP_UUID), NAP_HASH, sizeof(NAP_HASH));
  if(rc != EOK)
  {
    ERR_CHK(rc);
    return writer;
  }
  writer = avro_writer_memory( (char*)&AvroNAPSerializedBuf[MAGIC_NUMBER_SIZE + SCHEMA_ID_LENGTH],
                               sizeof(AvroNAPSerializedBuf) - MAGIC_NUMBER_SIZE - SCHEMA_ID_LENGTH );

  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

  return writer;
}


/* function call from harvester with parameters */
void harvester_report_neighboringap(struct neighboringapdata *head)
{
  int i, j, k = 0;
  uint8_t* b64buffer =  NULL;
  size_t decodesize = 0;
  int numElements = 0;
  int numDevices = 0;
  wifi_neighbor_ap2_t *ps = NULL;
  struct neighboringapdata* ptr = head;
  avro_writer_t writer;
  char * serviceName = "harvester";
  char * dest = "event:raw.kestrel.GatewayAccessPointNeighborScanReport";
  uuid_t transaction_id;
  char trans_id[37] = {0};
  char * contentType = "avro/binary"; // contentType "application/json", "avro/binary"
  errno_t rc = -1;

  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));

  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Head [%lx] \n", (ulong)head));

  numElements = NumberofNAPElementsinLinkedList(head);
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, prepare 2 enter Head [0x%lx] \n", (ulong)ptr ));
  numDevices = NumberofNAPDevicesinLinkedList(head);
  numDevices = numDevices; // get rid of warning if NO print
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, prepare 3 enter Head [0x%lx] \n", (ulong)ptr));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, numElements = %d\n", numElements ));

  OneAvroNAPSerializedSize = 0;

  // goes thru total number of elements in link list 
  writer = prepare_nap_writer();


  //Reset out writer
  avro_writer_reset(writer);

  //neighborAp Device Report
  avro_value_t  adr = {0}; /*RDKB-7464, CID-33485, init before use */
  avro_generic_value_new(iface, &adr);
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AccessPointNeighborScanReports\tType: %d\n", avro_value_get_type(&adr)));

  avro_value_t  adrField = {0}; /*RDKB-7464, CID-33485, init before use */

  //MAC
  /* Get CPE mac address, do it only pointer is NULL */
  if ( macStr == NULL )
  {
    macStr = getDeviceMac();
    pthread_mutex_lock(&avropack_mutex);
    rc = strcpy_s(CpemacStr,sizeof(CpemacStr),macStr);
    pthread_mutex_unlock(&avropack_mutex);
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
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Mac address = %0x\n", CpeMacid[ k ] ));
  }
  avro_value_get_by_name(&adr, "gateway_mac", &adrField, NULL);
  avro_value_set_fixed(&adrField, CpeMacid, 6);
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, gateway_mac\tType: %d\n", avro_value_get_type(&adrField)));
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  //Polling Period
  avro_value_get_by_name(&adr, "polling_interval", &adrField, NULL);
  avro_value_set_int(&adrField, GetNAPPollingPeriod() * 1000);
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, polling_interval\tType: %d\n", avro_value_get_type(&adrField)));
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  //Reporting Period
  avro_value_get_by_name(&adr, "reporting_interval", &adrField, NULL);
  avro_value_set_int(&adrField, GetNAPReportingPeriod() * 1000);
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, reporting_interval\tType: %d\n", avro_value_get_type(&adrField)));
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  //Array of device reports
  avro_value_get_by_name(&adr, "AccessPointNeighborScanReports", &adrField, NULL);
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AccessPointNeighborScanReports\tType: %d\n", avro_value_get_type(&adrField)));
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  //adrField now contains a reference to the neighborApDeviceReportsArray
  //Device Report
  avro_value_t dr = {0}; /*RDKB-7464, CID-33030, init before use */

  //Current Device Report Field
  avro_value_t drField = {0}; /*RDKB-7464, CID-32926, init before use */

  //Optional value for unions
  avro_value_t optional = {0}; /*RDKB-7464, CID-32962, init before use */

  for (i = 0; i < numElements; i++)
  {
    for (j = 0, ps = ptr->napdata; j < ptr->numNeibouringAP; j++, ps++)
    {

      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Current Link List Ptr = [0x%lx], numDevices = %d\n", (ulong)ptr, numDevices ));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, \tDevice entry #: %d\n", i + 1));

      //Append a DeviceReport item to array
      //avro_value_reset(&adrField);
      avro_value_append(&adrField, &dr, NULL);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, \tAccessPointNeighborScanReport\tType: %d\n", avro_value_get_type(&dr)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //Timestamp
      avro_value_get_by_name(&dr, "timestamp", &drField, NULL);
      int64_t tstamp_av = (int64_t) ptr->timestamp.tv_sec * 1000000 + (int64_t) ptr->timestamp.tv_usec;
      tstamp_av = tstamp_av/1000;
      avro_value_set_long(&drField, tstamp_av);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, \t\ttimestamp\tType: %d\n", avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //radio_bssid
      char bssidShortened[ 20 ] = {0};
      unsigned char bssid[ 6 ] = {0};
      for (k = 0; k < 6; k++ )
      {
        /* skip the : */
        bssidShortened[ k * 2 ] = ps->ap_BSSID[ k * 2 ];
        bssidShortened[ k * 2 + 1 ] = ps->ap_BSSID[ k * 2 + 1 ];
        bssid[ k ] = (int)strtol(&bssidShortened[ k * 2 ], NULL, 16);
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, BSSID Mac address = %x\n", bssid[ k ] ));

      }


      avro_value_get_by_name(&dr, "bssid_mac", &drField, NULL);
      avro_value_set_fixed(&drField, bssid, 6);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, \t\tbssid_mac\tType: %d\n", avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //ssid_name
      avro_value_get_by_name(&dr, "ssid_name", &drField, NULL);
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_string(&optional, ps->ap_SSID);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,\t\tAP ssid_name\tType: %d\n",avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //mode
      avro_value_get_by_name(&dr, "mode", &drField, NULL);
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_string(&optional, ps->ap_Mode);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, \t\tMode\tType: %d\n",avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //radio_channel
      avro_value_get_by_name(&dr, "radio_channel", &drField, NULL);
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_int(&optional, ps->ap_Channel);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, \t\tradio_channel\tType: %d\n",avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //signal_strength
      avro_value_get_by_name(&dr, "signal_strength", &drField, NULL);
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_int(&optional, ps->ap_SignalStrength);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, \t\tsignal_strength\tType: %d\n",avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //SecurityModeEnabled
      avro_value_get_by_name(&dr, "security_mode_enabled", &drField, NULL);
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_string(&optional, ps->ap_SecurityModeEnabled);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, \t\tSecurityModeEnabled\tType: %d\n",avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //EncryptionMode
      avro_value_get_by_name(&dr, "encryption_mode", &drField, NULL);
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_string(&optional, ps->ap_EncryptionMode);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, \t\tMode\tType: %d\n",avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //OperatingFrequencyBands
      avro_value_get_by_name(&dr, "operating_frequency_band", &drField, NULL);
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_string(&optional, ps->ap_OperatingFrequencyBand );
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, \t\tOperatingFrequencyBands\tType: %d\n",avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //SupportedStandards
      avro_value_get_by_name(&dr, "supported_standards", &drField, NULL);
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_string(&optional, ps->ap_SupportedStandards);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, \t\tSupportedStandards\tType: %d\n",avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //operating_standard
      avro_value_get_by_name(&dr, "operating_standards", &drField, NULL);
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_enum(&optional,avro_schema_enum_get_by_name(avro_value_get_schema(&optional), ps->ap_OperatingStandards));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, \t\toperating_standards\tType: %d\n",avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //operating_channel_bandwidth
      rc = strcpy_s(ps->ap_OperatingChannelBandwidth,sizeof(ps->ap_OperatingChannelBandwidth),"_20MHz");
      if(rc != EOK)
      {
          ERR_CHK(rc);
          return;
      }
      avro_value_get_by_name(&dr, "operating_channel_bandwidth", &drField, NULL);
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_enum(&optional,avro_schema_enum_get_by_name(avro_value_get_schema(&optional), ps->ap_OperatingChannelBandwidth));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, \t\toperating_channel_bandwidth\tType: %d\n",avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //BeaconPeriod
      avro_value_get_by_name(&dr, "beacon_period", &drField, NULL);
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_int(&optional, ps->ap_BeaconPeriod);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, \t\tBeaconPeriod\tType: %d\n",avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //Noise
      avro_value_get_by_name(&dr, "noise", &drField, NULL);
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_int(&optional, ps->ap_Noise);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, \t\tNoise\tType: %d\n",avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //BasicDataTransferRates
      avro_value_get_by_name(&dr, "basic_data_transfer_rates", &drField, NULL);
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_string(&optional, ps->ap_BasicDataTransferRates);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, \t\tBasicDataTransferRates\tType: %d\n",avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //SupportedDataTransferRate
      avro_value_get_by_name(&dr, "supported_data_transfer_rates", &drField, NULL);
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_string(&optional, ps->ap_SupportedDataTransferRates);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, \t\tSupportedDataTransferRate\tType: %d\n",avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //DTIMPeriod
      avro_value_get_by_name(&dr, "dtim_period", &drField, NULL);
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_int(&optional, ps->ap_DTIMPeriod);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, \t\tDTIMPeriod\tType: %d\n",avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //Channel_utilization
      avro_value_get_by_name(&dr, "channel_utilization", &drField, NULL);
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_int(&optional, ps->ap_ChannelUtilization);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, \t\tChannelUtilization\tType: %d\n",avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
    }
    ptr = ptr->next; // next link list

    /* check for writer size, if buffer is almost full, skip trailing linklist */
    avro_value_sizeof(&adr, &AvroNAPSerializedSize);
    OneAvroNAPSerializedSize = ( OneAvroNAPSerializedSize == 0 ) ? AvroNAPSerializedSize : OneAvroNAPSerializedSize;

    if ( ( WRITER_BUF_SIZE - AvroNAPSerializedSize ) < OneAvroNAPSerializedSize )
    {
      CcspHarvesterTrace(("RDK_LOG_ERROR, AVRO write buffer is almost full, size = %d func %s, exit!\n", (int)AvroNAPSerializedSize, __FUNCTION__ ));
      break;
    }

  }

  //Thats the end of that
  avro_value_write(writer, &adr);

  avro_value_sizeof(&adr, &AvroNAPSerializedSize);
  AvroNAPSerializedSize += MAGIC_NUMBER_SIZE + SCHEMA_ID_LENGTH;
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Serialized writer size %d\n", (int)AvroNAPSerializedSize));

  //Free up memory
  avro_value_decref(&adr);
  avro_writer_free(writer);
  //free(nap_schema_buffer);

  // b64 encoding
  decodesize = b64_get_encoded_buffer_size( AvroNAPSerializedSize );
  b64buffer = malloc(decodesize * sizeof(uint8_t));
  b64_encode( (uint8_t*)AvroNAPSerializedBuf, AvroNAPSerializedSize, b64buffer);

  if ( consoleDebugEnable )
  {
    fprintf( stderr, "\nAVro serialized data\n");
    for (k = 0; k < (int)AvroNAPSerializedSize ; k++)
    {
      char buf[30];
      if ( ( k % 32 ) == 0 )
        fprintf( stderr, "\n");
      rc = sprintf_s(buf,sizeof(buf),"%02X", (unsigned char)AvroNAPSerializedBuf[k]);
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
  
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Before NAP WebPA SEND message call\n"));

  uuid_generate_random(transaction_id); 
  uuid_unparse(transaction_id, trans_id);
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, serviceName: %s\n", serviceName));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, dest: %s\n", dest));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, trans_id: %s\n", trans_id));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, contentType: %s\n", contentType));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AvroNAPSerializedBuf: %s\n", AvroNAPSerializedBuf));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AvroNAPSerializedSize: %d\n", (int)AvroNAPSerializedSize));
  // Send data from Harvester to webpa using CCSP bus interface
  sendWebpaMsg(serviceName, dest, trans_id, contentType, AvroNAPSerializedBuf , AvroNAPSerializedSize);

  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, After NAP WebPA SEND message call\n"));

  free(b64buffer);

  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

}

void ap_avro_cleanup()
{
  if(nap_schema_buffer != NULL) {
        free(nap_schema_buffer); 
        nap_schema_buffer=NULL;
  } 
  if(iface != NULL){
        avro_value_iface_decref(iface);
        iface = NULL;
  }
  nap_schema_file_parsed = FALSE;
}

