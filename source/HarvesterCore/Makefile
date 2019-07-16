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

include $(CCSP_ROOT_DIR)/arch/ccsp_common.mk

#
#	Set up include directories
#

INCPATH += $(CCSP_ROOT_DIR)/hal/include
INCPATH += $(CCSP_ROOT_DIR)/Harvester/source/HarvesterSsp/
INCPATH += $(CCSP_ROOT_DIR)/Harvester/include/

CFLAGS += $(addprefix -I, $(INCPATH))
CFLAGS += -Wall

LDFLAGS+= -lccsp_common -lm -lpthread -lHarvesterSsp -lavro -lhal_wifi -lmsgpack -lbase64

ARRIS_LDFLAGS  = -L$(RDK_PROJECT_ROOT_PATH)/oem/patches/atom/oem/project_build_i686/IntelCE/root/usr/lib
ARRIS_LDFLAGS += -larris_rdk_wifi_api

LDFLAGS += $(ARRIS_LDFLAGS)

target := $(ComponentBuildDir)/harvester
source_files := $(call add_files_from_base,,'*.c')
obj_files := $(addprefix $(ComponentBuildDir)/, $(source_files:%.c=%.o))
-include $(obj_files:.o=.d)
$(target): $(obj_files)

#
#	Build targets
#

all: $(target) install
.PHONY: all clean

clean:
	rm -Rf $(ComponentBuildDir)

install:
	@echo "Copying harvester to atom"
	@install -d -m 0755 $(CCSP_OUT_DIR)/harvester
	@cp -f $(target) $(CCSP_OUT_DIR)/harvester
	@cp -f $(CCSP_ROOT_DIR)/Harvester/arch/intel_usg/boards/rdkb_atom/config/comcast/Harvester.XML $(CCSP_OUT_DIR)/harvester
	@cp -f $(CCSP_ROOT_DIR)/Harvester/arch/intel_usg/boards/rdkb_atom/config/GatewayAccessPointNeighborScanReport.avsc $(CCSP_OUT_DIR)/harvester
	@cp -f $(CCSP_ROOT_DIR)/Harvester/arch/intel_usg/boards/rdkb_atom/config/GatewayAssociatedDeviceReport.avsc $(CCSP_OUT_DIR)/harvester
	@cp -f $(CCSP_ROOT_DIR)/Harvester/arch/intel_usg/boards/rdkb_atom/config/GatewayWifiRadioReport.avsc $(CCSP_OUT_DIR)/harvester

#
# include custom post makefile, if exists
#
ifneq ($(findstring $(CCSP_CMPNT_BUILD_CUSTOM_MK_POST), $(wildcard $(ComponentBoardDir)/*.mk)), )
    include $(ComponentBoardDir)/$(CCSP_CMPNT_BUILD_CUSTOM_MK_POST)
endif

