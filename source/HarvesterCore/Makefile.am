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
bin_PROGRAMS = harvester

harvester_SOURCES = harvester.c

harvester_LDADD = ${top_builddir}/source/HarvesterSsp/libHarvesterSsp.la
harvester_CFLAGS = -I${top_srcdir}/include

if RDK_ONEWIFI
harvester_CFLAGS += -I${top_srcdir}/source/HarvesterSsp
endif
