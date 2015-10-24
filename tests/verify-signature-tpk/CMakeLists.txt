# Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
# @file        CMakeLists.txt
# @author      Kyungwook Tak (k.tak@samsung.com)
# @version     1.0
# @brief       makefile for cert-svc verify signature tests
#

SET(VERIFY_SIG_TPK_TESTS_DIR ${CMAKE_CURRENT_SOURCE_DIR})

SET(VERIFY_SIG_TPK_TESTS_SOURCES
	main.cpp
	verify-signature.cpp
	${VCORE_DPL_SOURCES}
	)

INCLUDE_DIRECTORIES(
	${PROJECT_SOURCE_DIR}/include
	${PROJECT_SOURCE_DIR}/vcore/src
	)

ADD_EXECUTABLE(${TARGET_VERIFY_SIG_TPK_TEST} ${VERIFY_SIG_TPK_TESTS_SOURCES})

TARGET_LINK_LIBRARIES(${TARGET_VERIFY_SIG_TPK_TEST}
	${TARGET_CERT_SVC_LIB}
	${TARGET_VCORE_LIB}
	${VCORE_TEST_DEP_LIBRARIES}
	)

INSTALL(TARGETS ${TARGET_VERIFY_SIG_TPK_TEST}
	DESTINATION /usr/bin
	PERMISSIONS
		OWNER_READ
		OWNER_WRITE
		OWNER_EXECUTE
		GROUP_READ
		GROUP_EXECUTE
		WORLD_READ
		WORLD_EXECUTE
	)

INSTALL(
	DIRECTORY
		resource/normal-tpk
		resource/attacked-tpk
		resource/normal-tpk-with-userdata
		resource/attacked-tpk-with-userdata
	DESTINATION
		/opt/apps/tpk/tests/verify-sig-tpk
	)
