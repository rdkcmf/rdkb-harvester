##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2019 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
lib_LTLIBRARIES=libHarvesterSsp.la

libHarvesterSsp_la_SOURCES = cosa_harvester_dml.c  \
                             harvester_associated_devices.c  \
                             harvester_neighboring_ap.c   \
                             harvester_neighboring_ap_ondemand.c   \
                             harvester_radio_traffic.c   \
                             plugin_main.c  \
                             ssp_main.c \
                             webpa_interface.c \
                             webpa_interface_with_seshat.c \
                             webpa_interface_without_seshat.c \
                             cosa_harvester_internal.c  \
                             harvester_associated_devices_avropack.c  \
                             harvester_neighboring_ap_avropack.c  \
                             harvester_radio_traffic_avropack.c  \
                             ssp_action.c   \
                             ssp_messagebus_interface.c  \
                             dm_pack_datamodel.c
if RDK_ONEWIFI
libHarvesterSsp_la_SOURCES += harvester_rbus_api.c
endif

libHarvesterSsp_la_LDFLAGS = -lccsp_common -lm -lpthread -lavro -lhal_wifi -lmsgpackc -ltrower-base64 -luuid -lsecure_wrapper
libHarvesterSsp_la_CFLAGS = -I${top_srcdir}/include
