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
INCPATH += $(CCSP_ROOT_DIR)/ExtDependency/opensource_work/intel_usg/rdkb_atom/avro-c/src
INCPATH += $(CCSP_ROOT_DIR)/ExtDependency/opensource_work/intel_usg/rdkb_atom/msgpack/include
INCPATH += $(CCSP_ROOT_DIR)/ExtDependency/opensource_work/intel_usg/rdkb_atom/base64
CFLAGS += $(addprefix -I, $(INCPATH))


CFLAGS += -Wall

LDFLAGS+= -lccsp_common -lm -lpthread -lavro -lhal_wifi -lmsgpack -lbase64

target := $(ComponentBuildDir)/libHarvesterSsp.so
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
	@echo "Installing library"
	@echo "Copying HarvesterSsp.so lib to atom"
	@cp $(target) $(CCSP_ROOT_DIR)/Stage/intel_usg-rdkb_atom/lib
	@cp -f $(target) $(CCSP_OUT_DIR)/


#
# include custom post makefile, if exists
#
ifneq ($(findstring $(CCSP_CMPNT_BUILD_CUSTOM_MK_POST), $(wildcard $(ComponentBoardDir)/*.mk)), )
    include $(ComponentBoardDir)/$(CCSP_CMPNT_BUILD_CUSTOM_MK_POST)
endif

