# Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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
# @author      Jacek Migacz (j.migacz@samsung.com)
# @version     1.0
# @brief       This package provides bacis check of internal OpenSSL's PKCS#12 routines.
#
INCLUDE(FindPkgConfig)
SET(TARGET_PKCS12_TEST "cert-svc-tests-pkcs12")
SET(TARGET_PKCS12_TEST_AUX "cert-svc-tests-pkcs12-aux")

ADD_DEFINITIONS("-DDPL_LOGS_ENABLED")

PKG_CHECK_MODULES(PKCS12_TEST_DEP
    libsoup-2.4
    dpl-test-efl
    dpl-db-efl
    libpcrecpp
    secure-storage
    REQUIRED
    )

SET(PKCS12_TEST_SOURCES
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/pkcs12_test.cpp
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/test_cases.cpp
    )

INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/vcore/src
    ${PROJECT_SOURCE_DIR}/tests/pkcs12
    ${PKCS12_TEST_DEP_INCLUDE_DIRS}
    ${VCOREC_TEST_DEP_INCLUDE_DIRS}
    )

ADD_EXECUTABLE(${TARGET_PKCS12_TEST} ${PKCS12_TEST_SOURCES})

TARGET_LINK_LIBRARIES(${TARGET_PKCS12_TEST}
    ${TARGET_PKCS12_TEST_LIB}
    ${PKCS12_TEST_DEP_LIBRARIES}
    ${TARGET_VCORE_LIB}
    ${VCOREC_TEST_DEP_LIBRARIES}
    )

INSTALL(TARGETS ${TARGET_PKCS12_TEST}
    DESTINATION /usr/bin
    PERMISSIONS OWNER_READ
                OWNER_WRITE
                OWNER_EXECUTE
                GROUP_READ
                GROUP_EXECUTE
                WORLD_READ
                WORLD_EXECUTE
    )


SET(PKCS12_TEST_SOURCES_AUX
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/pkcs12_test.cpp
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/aux_test.cpp
    )

INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/vcore/src
    ${PROJECT_SOURCE_DIR}/tests/pkcs12
    ${PKCS12_TEST_DEP_INCLUDE_DIRS}
    ${VCOREC_TEST_DEP_INCLUDE_DIRS}
)

ADD_EXECUTABLE(${TARGET_PKCS12_TEST_AUX} ${PKCS12_TEST_SOURCES_AUX})

TARGET_LINK_LIBRARIES(
    ${TARGET_PKCS12_TEST_AUX}
    ${TARGET_PKCS12_TEST_LIB}
    ${PKCS12_TEST_DEP_LIBRARIES}
    ${TARGET_VCORE_LIB}
    ${VCOREC_TEST_DEP_LIBRARIES}
)

INSTALL(TARGETS ${TARGET_PKCS12_TEST_AUX}
    DESTINATION /usr/bin
    PERMISSIONS OWNER_READ
                OWNER_WRITE
                OWNER_EXECUTE
                GROUP_READ
                GROUP_EXECUTE
                WORLD_READ
                WORLD_EXECUTE
    )

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/test.p12
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/with_pass.p12
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/without_pass.p12
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/eastest036.pfx
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/Maha.pfx
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/filip.pkcs12
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/tizen_test_certs.p12
    DESTINATION /opt/apps/widget/tests/pkcs12/
)
