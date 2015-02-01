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
# @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
# @version     1.0
# @brief
#
INCLUDE(FindPkgConfig)
SET(TARGET_TEST_CERT_SVC_OGIG "cert-svc-tests-orig")

PKG_CHECK_MODULES(VCOREC_TEST_DEP
    libsoup-2.4
    dpl-test-efl
    dpl-db-efl
    libpcrecpp
    REQUIRED
    )

SET(CERT_SVC_OGIG_TESTS_SOURCES
    ${PROJECT_SOURCE_DIR}/tests/cert-svc/test_caflag.c
    ${PROJECT_SOURCE_DIR}/tests/cert-svc/test_ocsp.c
    ${PROJECT_SOURCE_DIR}/tests/cert-svc/test_suite_main.c
    )

INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/tests/cert-svc
    ${PROJECT_SOURCE_DIR}/include
    )

ADD_EXECUTABLE(${TARGET_TEST_CERT_SVC_OGIG} ${CERT_SVC_OGIG_TESTS_SOURCES})

ADD_DEFINITIONS("-DDPL_LOGS_ENABLED")
IF(TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)
ADD_DEFINITIONS("-DTIZEN_FEATURE_CERT_SVC_OCSP_CRL")
ENDIF()

TARGET_LINK_LIBRARIES(
    ${TARGET_TEST_CERT_SVC_OGIG}
    ${TARGET_CERT_SVC_LIB}
    ${CERT_SVC_DEPS_LIBRARIES}
    )

INSTALL(TARGETS ${TARGET_TEST_CERT_SVC_OGIG}
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
    ${PROJECT_SOURCE_DIR}/tests/cert-svc/data/caflag/second_ca.der
    ${PROJECT_SOURCE_DIR}/tests/cert-svc/data/caflag/aia_signer.der
    ${PROJECT_SOURCE_DIR}/tests/cert-svc/data/caflag/rev_signer.der
    ${PROJECT_SOURCE_DIR}/tests/cert-svc/data/caflag/noaia_signer.der
    ${PROJECT_SOURCE_DIR}/tests/cert-svc/data/caflag/v1_signer.der
    DESTINATION /opt/share/cert-svc/tests/orig_c/data/caflag
    PERMISSIONS OWNER_READ
                GROUP_READ
                WORLD_READ
    )

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/tests/cert-svc/data/caflag/root_ca.der
    ${PROJECT_SOURCE_DIR}/tests/cert-svc/data/caflag/root_ca_v1.der
    ${PROJECT_SOURCE_DIR}/tests/cert-svc/data/ocsp/second_ca.der
    DESTINATION /opt/share/cert-svc/certs
    PERMISSIONS OWNER_READ
                GROUP_READ
                WORLD_READ
    )  

IF(TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)
INSTALL(DIRECTORY
    ${PROJECT_SOURCE_DIR}/tests/cert-svc/data/ocsp/
    DESTINATION /opt/share/cert-svc/tests/orig_c/data/ocsp
    FILES_MATCHING
    PATTERN "*" 
    PERMISSIONS OWNER_READ
                OWNER_WRITE
                OWNER_EXECUTE
                GROUP_READ
                GROUP_EXECUTE
                WORLD_READ
                WORLD_EXECUTE
    )
    
INSTALL(FILES 
    ${PROJECT_SOURCE_DIR}/tests/cert-svc/data/ocsp/cert-svc-tests-start-ocsp-server.sh
    ${PROJECT_SOURCE_DIR}/tests/cert-svc/data/ocsp/cert-svc-tests-kill-ocsp-server.sh
    DESTINATION /usr/bin
    PERMISSIONS OWNER_READ
                OWNER_WRITE
                OWNER_EXECUTE
                GROUP_READ
                GROUP_EXECUTE
                WORLD_READ
                WORLD_EXECUTE
    )
ENDIF()  
   
