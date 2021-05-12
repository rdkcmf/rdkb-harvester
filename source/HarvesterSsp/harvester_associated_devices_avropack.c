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


#define MAGIC_NUMBER      0x85
#define MAGIC_NUMBER_SIZE 1
#define SCHEMA_ID_LENGTH  32
#define WRITER_BUF_SIZE   1024 * 30 // 30K

// HASH - a0fe2a90307541ad0b03411f52ccfd07
// UUID - ec57a5b6-b167-4623-baff-399f063bd56a

uint8_t HASH[16] = {0xa0, 0xfe, 0x2a, 0x90, 0x30, 0x75, 0x41, 0xad,
                    0x0b, 0x03, 0x41, 0x1f, 0x52, 0xcc, 0xfd, 0x07
                   };

uint8_t UUID[16] = {0xec, 0x57, 0xa5, 0xb6, 0xb1, 0x67, 0x46, 0x23,
                    0xba, 0xff, 0x39, 0x9f, 0x06, 0x3b, 0xd5, 0x6a
                   };


// local data, load it with real data if necessary
char ReportSource[] = "harvester";
char CPE_TYPE_STRING[] = "Gateway";
char PARENT_CPE_TYPE_STRING[] = "Extender";
char DEVICE_TYPE[] = "WiFi";
char ParentCpeMacid[] = { 0x77, 0x88, 0x99, 0x00, 0x11, 0x22 };
int cpe_parent_exists = FALSE;
// local data, load it with real data if necessary

/**** temperatory raw data ****/

#if !defined(UTC_ENABLE_ATOM) && !defined(_HUB4_PRODUCT_REQ_)
extern int getTimeOffsetFromUtc();
#endif

static char *macStr = NULL;
static char CpemacStr[ 32 ];
char *buffer = NULL;
char *idw_schemaidbuffer = "ec57a5b6-b167-4623-baff-399f063bd56a/a0fe2a90307541ad0b03411f52ccfd07";
static avro_value_iface_t  *iface = NULL;
BOOL schema_file_parsed = FALSE;
size_t AvroSerializedSize;
size_t OneAvroSerializedSize;
char AvroSerializedBuf[ WRITER_BUF_SIZE ];

char* GetIDWSchemaBuffer()
{
  return buffer;
}

int GetIDWSchemaBufferSize()
{
int len = 0;
if(buffer)
  len = strlen(buffer);
  
return len;
}

char* GetIDWSchemaIDBuffer()
{
  return idw_schemaidbuffer;
}

int GetIDWSchemaIDBufferSize()
{
int len = 0;
if(idw_schemaidbuffer)
        len = strlen(idw_schemaidbuffer);

return len;
}

int NumberofElementsinLinkedList(struct associateddevicedata* head)
{
  int numelements = 0;
  struct associateddevicedata* ptr  = head;
  while (ptr != NULL)
  {
    numelements++;
    ptr = ptr->next;
  }
  return numelements;
}


ULONG NumberofDevicesinLinkedList(struct associateddevicedata* head)
{
  ULONG numdevices = 0;
  struct associateddevicedata* ptr  = head;
  while (ptr != NULL)
  {
    numdevices = numdevices + ptr->numAssocDevices;
    ptr = ptr->next;
  }
  return numdevices;
}

avro_writer_t prepare_writer()
{
  avro_writer_t writer = {0};
  long lSize = 0;
  errno_t rc = -1;

  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Avro prepares to serialize data\n"));

  if ( schema_file_parsed == FALSE )
  {
    FILE *fp;

    /* open schema file */
    fp = fopen ( INTERFACE_DEVICES_WIFI_AVRO_FILENAME , "rb" );
    if ( !fp ) perror( INTERFACE_DEVICES_WIFI_AVRO_FILENAME " doesn't exist."), exit(1);

    /* seek through file and get file size*/
    fseek( fp , 0L , SEEK_END);
    lSize = ftell( fp );
    /* CID: 69140 Argument cannot be negative*/
    if (lSize < 0) 
        fclose(fp), fputs("lSize is negative value", stderr), exit(1);

    /*back to the start of the file*/
    rewind( fp );

    /* allocate memory for entire content */
    buffer = calloc( 1, lSize + 1 );

    if ( !buffer ) fclose(fp), fputs("memory alloc fails", stderr), exit(1);

    /* copy the file into the buffer */
    if ( 1 != fread( buffer , lSize, 1 , fp) )
      fclose(fp), free(buffer), fputs("entire read fails", stderr), exit(1);

    fclose(fp);

    /* CID:135642 String not null terminated*/
    buffer [lSize]= '\0';

    //schemas
    avro_schema_error_t  error = NULL;

    //Master report/datum
    avro_schema_t associated_device_report_schema = NULL;
    avro_schema_from_json(buffer, strlen(buffer),
                        &associated_device_report_schema, &error);

    //generate an avro class from our schema and get a pointer to the value interface
    iface = avro_generic_class_from_schema(associated_device_report_schema);

    avro_schema_decref(associated_device_report_schema);
    schema_file_parsed = TRUE; // parse schema file once only
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Read Avro schema file ONCE, lSize = %ld, pbuffer = 0x%lx.\n", lSize + 1, (ulong)buffer ));
  }
  else
  {
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Stored lSize = %ld, pbuffer = 0x%lx.\n", lSize + 1, (ulong)buffer ));
  }

  rc = memset_s(&AvroSerializedBuf[0], sizeof(AvroSerializedBuf), 0, sizeof(AvroSerializedBuf));
  ERR_CHK(rc);

  AvroSerializedBuf[0] = MAGIC_NUMBER; /* fill MAGIC number = Empty, i.e. no Schema ID */

  rc = memcpy_s(&AvroSerializedBuf[ MAGIC_NUMBER_SIZE ], sizeof(AvroSerializedBuf)-MAGIC_NUMBER_SIZE, UUID, sizeof(UUID));
  if(rc != EOK)
  {
    ERR_CHK(rc);
    return writer;
  }
  rc = memcpy_s(&AvroSerializedBuf[ MAGIC_NUMBER_SIZE + sizeof(UUID) ], sizeof(AvroSerializedBuf)-MAGIC_NUMBER_SIZE-sizeof(UUID), HASH, sizeof(HASH));
  if(rc != EOK)
  {
    ERR_CHK(rc);
    return writer;
  }

  writer = avro_writer_memory( (char*)&AvroSerializedBuf[MAGIC_NUMBER_SIZE + SCHEMA_ID_LENGTH],
                               sizeof(AvroSerializedBuf) - MAGIC_NUMBER_SIZE - SCHEMA_ID_LENGTH );

  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

  return writer;
}


/* function call from harvester with parameters */
void harvester_report_associateddevices(struct associateddevicedata *head, char* ServiceType)
{
  int i, j, k = 0;
  uint8_t* b64buffer =  NULL;
  size_t decodesize = 0;
  int numElements = 0;
  int numDevices = 0;
  wifi_associated_dev_t *ps = NULL;
  struct associateddevicedata* ptr = head;
  avro_writer_t writer;
  char * serviceName = "harvester";
  char * dest = "event:raw.kestrel.reports.InterfaceDevicesWifi";
  char * contentType = "avro/binary"; // contentType "application/json", "avro/binary"
  uuid_t transaction_id;
  char trans_id[37];
  errno_t rc = -1;
  int ind = -1;
  size_t strsize2_4GHZ = 0;
  size_t strsize5GHZ = 0;
#ifdef WIFI_HAL_VERSION_3
  size_t strsize6GHZ = 0;
#endif

  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : ENTER \n", __FUNCTION__ ));

  numElements = NumberofElementsinLinkedList(head);
  numDevices = NumberofDevicesinLinkedList(head);
  numDevices = numDevices; // get rid of warning if NO print

  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, numElements = %d\n", numElements ));

  OneAvroSerializedSize = 0;

  /* goes thru total number of elements in link list */
  writer = prepare_writer();


  //Reset out writer
  avro_writer_reset(writer);

  //Associated Device Report
  avro_value_t  adr = {0}; /*RDKB-7463, CID-33353, init before use */
  avro_generic_value_new(iface, &adr);

  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, GatewayAssociatedDeviceReport\tType: %d\n", avro_value_get_type(&adr)));

  avro_value_t  adrField = {0}; /*RDKB-7463, CID-33485, init before use */

  //Optional value for unions, mac address is an union
  avro_value_t optional  = {0}; /*RDKB-7463, CID-32938, init before use */

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
   /* Coverity Fix CID: 124833  PRINTF_ARGS*/ 
#ifdef _64BIT_ARCH_SUPPORT_
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, timestamp = %ld\n", tstamp_av_main ));
#else
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, timestamp = %lld\n", tstamp_av_main ));
#endif
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, timestamp = ""%" PRId64 "\n", tstamp_av_main ));

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
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Associate Device Reports - data array\tType: %d\n", avro_value_get_type(&adrField)));
  if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

  //adrField now contains a reference to the Interface WiFi ReportsArray
  //Device Report
  avro_value_t dr = {0}; /*RDKB-7463, CID-33085, init before use */

  //Current Device Report Field
  avro_value_t drField = {0}; /*RDKB-7463, CID-33269, init before use */

  //interference sources
  avro_value_t interferenceSource = {0}; /*RDKB-7463, CID-33062, init before use */

  strsize2_4GHZ = strlen("2.4GHz");
  strsize5GHZ = strlen("5GHz");
#ifdef WIFI_HAL_VERSION_3
  strsize6GHZ = strlen("6GHz");
#endif

  for (i = 0; i < numElements; i++)
  {
    for (j = 0, ps = ptr->devicedata; j < ptr->numAssocDevices; j++, ps++)
    {

      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Current Link List Ptr = [0x%lx], numDevices = %d\n", (ulong)ptr, numDevices ));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, \tDevice entry #: %d\n", i + 1));

      //Append a DeviceReport item to array
      avro_value_append(&adrField, &dr, NULL);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, \tInterface Report\tType: %d\n", avro_value_get_type(&dr)));

      //data array block

      //device_mac - fixed 6 bytes
      avro_value_get_by_name(&dr, "device_id", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, device_id\tType: %d\n", avro_value_get_type(&drField)));
      avro_value_get_by_name(&drField, "mac_address", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_fixed(&optional, ps->cli_MACAddress, 6);
      pMac = (unsigned char*)ps->cli_MACAddress;
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, mac_address = 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n", pMac[0], pMac[1], pMac[2], pMac[3], pMac[4], pMac[5] ));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, mac_address\tType: %d\n", avro_value_get_type(&optional)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //device_type - string
      avro_value_get_by_name(&dr, "device_id", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, device_id\tType: %d\n", avro_value_get_type(&drField)));
      avro_value_get_by_name(&drField, "device_type", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_set_string(&optional, DEVICE_TYPE);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, device_type = \"%s\"\n", DEVICE_TYPE ));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, device_type\tType: %d\n", avro_value_get_type(&optional)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //timestamp - long
      avro_value_get_by_name(&dr, "timestamp", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      int64_t tstamp_av = (int64_t) ptr->timestamp.tv_sec * 1000000 + (int64_t) ptr->timestamp.tv_usec;
      tstamp_av = tstamp_av/1000;
      avro_value_set_long(&optional, tstamp_av);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, timestamp = ""%" PRId64 "\n", tstamp_av ));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, timestamp\tType: %d\n", avro_value_get_type(&optional)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      // Service_type
      avro_value_get_by_name(&dr, "service_type", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Service_type\tType: %d\n", avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, service_type = \"%s\"\n", ServiceType ));
      avro_value_set_enum(&drField, avro_schema_enum_get_by_name(avro_value_get_schema(&drField), ServiceType));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      rc = memset_s(CpeMacHoldingBuf, sizeof(CpeMacHoldingBuf), 0, sizeof(CpeMacHoldingBuf));
      ERR_CHK(rc);
      rc = memset_s(CpeMacid, sizeof(CpeMacid), 0, sizeof(CpeMacid));
      ERR_CHK(rc);

      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Mac address BSSID  = %s \n", ptr->bssid ));

      for (k = 0; k < 6; k++ )
      {
        /* copy 2 bytes */
        CpeMacHoldingBuf[ k * 2 ] = ptr->bssid[ k * 3 ];
        CpeMacHoldingBuf[ k * 2 + 1 ] = ptr->bssid[ k * 3 + 1 ];
        CpeMacid[ k ] = (unsigned char)strtol(&CpeMacHoldingBuf[ k * 2 ], NULL, 16);
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Interface Mac address = %0x\n", CpeMacid[ k ] ));
      }

      // interface_mac
      avro_value_get_by_name(&dr, "interface_mac", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, interface_mac\tType: %d\n", avro_value_get_type(&drField)));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_fixed(&drField, CpeMacid, 6);
      pMac = (unsigned char*)CpeMacid;
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, interface_mac = 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n", pMac[0], pMac[1], pMac[2], pMac[3], pMac[4], pMac[5] ));
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //interface parameters block

      // operating standard
      avro_value_get_by_name(&dr, "interface_parameters", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "operating_standard", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, operating_standard\tType: %d\n", avro_value_get_type(&optional)));
      //Patch HAL values if necessary
      if ( strlen(ps->cli_OperatingStandard ) == 0 )      
      {
          CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, operating_standard = \"%s\"\n", "Not defined, set to NULL" ));
          avro_value_set_null(&optional);
      }
      else
      {
          CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, operating_standard = \"%s\"\n", ps->cli_OperatingStandard ));
          avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), ps->cli_OperatingStandard));
      }
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror())); 

      // operating channel bandwidth
      avro_value_get_by_name(&dr, "interface_parameters", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "operating_channel_bandwidth", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, operating_channel_bandwidth\tType: %d\n", avro_value_get_type(&optional)));
      //Patch HAL values if necessary
      if ( strstr("_20MHz", ps->cli_OperatingChannelBandwidth) )
      {
          CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, operating_channel_bandwidth = \"%s\"\n", "set to _20MHz" ));
          avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_20MHz"));
      }
      else if ( strstr("_40MHz", ps->cli_OperatingChannelBandwidth) )
      {
          CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, operating_channel_bandwidth = \"%s\"\n", "set to _40MHz" ));
          avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_40MHz"));
      }
      else if ( strstr("_80MHz", ps->cli_OperatingChannelBandwidth) )
      {
          CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, operating_channel_bandwidth = \"%s\"\n", "set to _80MHz" ));
          avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_80MHz"));
      }
      else if ( strstr("_160MHz", ps->cli_OperatingChannelBandwidth) )
      {
          CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, operating_channel_bandwidth = \"%s\"\n", "set to _160MHz" ));
          avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_160MHz"));
      }
      else
      {
          CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, operating_channel_bandwidth = \"%s\"\n", ps->cli_OperatingChannelBandwidth ));
          CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, operating_channel_bandwidth = \"%s\"\n", "Not defined in Schema, set to NULL" ));
          avro_value_set_null(&optional);
      }
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      // frequency band
      avro_value_get_by_name(&dr, "interface_parameters", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "frequency_band", &drField, NULL);
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

      // channel #
      avro_value_get_by_name(&dr, "interface_parameters", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "channel", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, channel = %ld\n", ptr->radioChannel));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, channel\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_int(&optional, ptr->radioChannel);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      // ssid
      avro_value_get_by_name(&dr, "interface_parameters", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "ssid", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, ssid = \"%s\"\n", ptr->sSidName ));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, ssid\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_string(&optional, ptr->sSidName);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //interface metrics block

      //WIFI - authenticated
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "authenticated", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, authenticated\tType: %d\n", avro_value_get_type(&optional)));
      if ( ps->cli_AuthenticationState )
      {
          CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, authenticated = TRUE\n"));
          avro_value_set_boolean(&optional, TRUE);
      }
      else
      {
          CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, authenticated = FALSE\n"));
          avro_value_set_boolean(&optional, FALSE);
      }
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //authentication failures
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "authentication_failures", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, authentication_failures = %d\n", ps->cli_AuthenticationFailures));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, authentication_failures\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_int(&optional, ps->cli_AuthenticationFailures);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //data_frames_sent_ack
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "data_frames_sent_ack", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, data_frames_sent_ack = %ld\n", ps->cli_DataFramesSentAck));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, data_frames_sent_ack\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_long(&optional, ps->cli_DataFramesSentAck);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //data_frames_sent_no_ack
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "data_frames_sent_no_ack", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, data_frames_sent_no_ack = %ld\n", ps->cli_DataFramesSentNoAck));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, data_frames_sent_no_ack\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_long(&optional, ps->cli_DataFramesSentNoAck);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //disassociations
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "disassociations", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, disassociations = %d\n", ps->cli_Disassociations));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, disassociations\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_int(&optional, ps->cli_Disassociations);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //interference_sources
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "interference_sources", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, interference_sources\tType: %d\n", avro_value_get_type(&drField)));
      if (strstr( ps->cli_InterferenceSources, "MicrowaveOven") != NULL )
      {
          CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, interference_sources = \"%s\"\n", "set to MicrowaveOven" ));
          avro_value_append(&drField, &interferenceSource, NULL);
          avro_value_set_string(&interferenceSource,"MicrowaveOven");
      }
      if (strstr( ps->cli_InterferenceSources, "CordlessPhone") != NULL )
      {
          CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, interference_sources = \"%s\"\n", "set to CordlessPhone" ));
          avro_value_append(&drField, &interferenceSource, NULL);
          avro_value_set_string(&interferenceSource,"CordlessPhone");
      }
      if (strstr( ps->cli_InterferenceSources, "BluetoothDevices") != NULL )
      {
          CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, interference_sources = \"%s\"\n", "set to BluetoothDevices" ));
          avro_value_append(&drField, &interferenceSource, NULL);
          avro_value_set_string(&interferenceSource,"BluetoothDevices");
      }
      if (strstr( ps->cli_InterferenceSources, "FluorescentLights") != NULL )
      {
          CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, interference_sources = \"%s\"\n", "set to FluorescentLights" ));
          avro_value_append(&drField, &interferenceSource, NULL);
          avro_value_set_string(&interferenceSource,"FluorescentLights");
      }
      if (strstr( ps->cli_InterferenceSources, "ContinuousWaves") != NULL )
      {
          CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, interference_sources = \"%s\"\n", "set to ContinuousWaves" ));
          avro_value_append(&drField, &interferenceSource, NULL);
          avro_value_set_string(&interferenceSource,"ContinuousWaves");
      }
      avro_value_append(&drField, &interferenceSource, NULL);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, interference_sources = \"%s\"\n", "also set to Others" ));
      avro_value_set_string(&interferenceSource,"Others");
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //rx_rate
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "rx_rate", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, rx_rate = %d\n", ps->cli_LastDataDownlinkRate));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, rx_rate\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_float(&optional, (float)ps->cli_LastDataDownlinkRate);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //tx_rate
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "tx_rate", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, tx_rate = %d\n", ps->cli_LastDataUplinkRate));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, tx_rate\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_float(&optional, (float)ps->cli_LastDataUplinkRate);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //retransmissions
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "retransmissions", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, retransmissions = %d\n", ps->cli_Retransmissions));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, retransmissions\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_int(&optional, ps->cli_Retransmissions);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //signal_strength
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "signal_strength", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, signal_strength = %d\n", ps->cli_SignalStrength));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, signal_strength\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_float(&optional, (float)ps->cli_SignalStrength);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      //snr
      avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      avro_value_get_by_name(&optional, "snr", &drField, NULL);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));
      avro_value_set_branch(&drField, 1, &optional);
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, snr = %d\n", ps->cli_SNR));
      CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, snr\tType: %d\n", avro_value_get_type(&optional)));
      avro_value_set_float(&optional, (float)ps->cli_SNR);
      if ( CHK_AVRO_ERR ) CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s\n", avro_strerror()));

      // All done with schema, next entry if any

    }
    ptr = ptr->next; // next link list

    /* check for writer size, if buffer is almost full, skip trailing linklist */
    avro_value_sizeof(&adr, &AvroSerializedSize);
    OneAvroSerializedSize = ( OneAvroSerializedSize == 0 ) ? AvroSerializedSize : OneAvroSerializedSize;

    if ( ( WRITER_BUF_SIZE - AvroSerializedSize ) < OneAvroSerializedSize )
    {
      CcspHarvesterTrace(("RDK_LOG_ERROR, AVRO write buffer is almost full, size = %d func %s, exit!\n", (int)AvroSerializedSize, __FUNCTION__ ));
      break;
    }

  }
  //Thats the end of that
  avro_value_write(writer, &adr);

  avro_value_sizeof(&adr, &AvroSerializedSize);
  AvroSerializedSize += MAGIC_NUMBER_SIZE + SCHEMA_ID_LENGTH;
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Serialized writer size %d\n", (int)AvroSerializedSize));

  //Free up memory
  avro_value_decref(&adr);
  avro_writer_free(writer);
  //free(buffer);

  if ( consoleDebugEnable )
  {

    /* b64 encoding */
    decodesize = b64_get_encoded_buffer_size( AvroSerializedSize );
    b64buffer = malloc(decodesize * sizeof(uint8_t));
    b64_encode( (uint8_t*)AvroSerializedBuf, AvroSerializedSize, b64buffer);

    fprintf( stderr, "\nAVro serialized data\n");
    for (k = 0; k < (int)AvroSerializedSize ; k++)
    {
      char buf[30];
      if ( ( k % 32 ) == 0 )
        fprintf( stderr, "\n");
      rc = sprintf_s(buf,sizeof(buf),"%02X", (unsigned char)AvroSerializedBuf[k]);
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
    free(b64buffer);
  }

  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Before AD WebPA SEND message call\n"));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, serviceName: %s\n", serviceName));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, dest: %s\n", dest));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, trans_id: %s\n", trans_id));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, contentType: %s\n", contentType));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AvroSerializedBuf: %s\n", AvroSerializedBuf));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, AvroSerializedSize: %d\n", (int)AvroSerializedSize));
  // Send data from Harvester to webpa using CCSP bus interface
  sendWebpaMsg(serviceName, dest, trans_id, contentType, AvroSerializedBuf, AvroSerializedSize);
  CcspHarvesterTrace(("RDK_LOG_WARN, InterfaceDevicesWifi report sent to Webpa, Destination=%s, Transaction-Id=%s  \n",dest,trans_id));
  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, After AD WebPA SEND message call\n"));


  CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s : EXIT \n", __FUNCTION__ ));

#if SIMULATION
  exit(0);
#endif
}

void harvester_avro_cleanup()

{
  if(buffer != NULL) {
        free(buffer); 
        buffer=NULL;
  } 
  if(iface != NULL){
        avro_value_iface_decref(iface);
        iface = NULL;
  }
  schema_file_parsed = FALSE;
}

