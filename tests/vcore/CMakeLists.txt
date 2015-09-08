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
# @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
# @author      Pawel Sikorski (p.sikorski@samsung.com)
# @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
# @version     1.0
# @brief
#
INCLUDE(FindPkgConfig)
SET(TARGET_VCORE_TEST "cert-svc-tests-vcore")

SET(VCORE_TESTS_SOURCES
    ${PROJECT_SOURCE_DIR}/tests/vcore/vcore_tests.cpp
    ${PROJECT_SOURCE_DIR}/tests/vcore/TestCases.cpp
    ${PROJECT_SOURCE_DIR}/tests/vcore/TestEnv.cpp
    ${PROJECT_SOURCE_DIR}/tests/vcore/file_input_mapping.cpp
    ${VCORE_DPL_SOURCES}
    )

IF(DEFINED TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)
SET(VCORE_TESTS_SOURCES
	${PROJECT_SOURCE_DIR}/tests/vcore/vcore_tests.cpp
    ${PROJECT_SOURCE_DIR}/tests/vcore/TestCases.cpp
    ${PROJECT_SOURCE_DIR}/tests/vcore/TestEnv.cpp
    ${PROJECT_SOURCE_DIR}/tests/vcore/file_input_mapping.cpp
	${PROJECT_SOURCE_DIR}/tests/vcore/TestCRL.cpp
    ${VCORE_DPL_SOURCES}
	)
ENDIF(DEFINED TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)

INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/vcore/src
    ${PROJECT_SOURCE_DIR}/tests/vcore
    ${VCORE_TEST_DEP_INCLUDE_DIRS}
    ${VCORE_DPL_INCLUDE}
    )

ADD_EXECUTABLE(${TARGET_VCORE_TEST} ${VCORE_TESTS_SOURCES})
TARGET_LINK_LIBRARIES(${TARGET_VCORE_TEST}
    ${SYS_EFL_LIBRARIES}
    ${TARGET_VCORE_LIB}
    ${VCORE_TEST_DEP_LIBRARIES}
    )

INSTALL(TARGETS ${TARGET_VCORE_TEST}
    DESTINATION /usr/bin
    PERMISSIONS OWNER_READ
                OWNER_WRITE
                OWNER_EXECUTE
                GROUP_READ
                GROUP_EXECUTE
                WORLD_READ
                WORLD_EXECUTE
    )

IF(DEFINED TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)
INSTALL(FILES ${PROJECT_SOURCE_DIR}/tests/vcore/cert-svc-tests-vcore-ocsp-server.sh
    DESTINATION /usr/bin
    PERMISSIONS OWNER_READ
                OWNER_WRITE
                OWNER_EXECUTE
                GROUP_READ
                GROUP_EXECUTE
                WORLD_READ
                WORLD_EXECUTE
    )
ENDIF(DEFINED TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)

ADD_CUSTOM_COMMAND(TARGET ${TARGET_VCORE_TEST} POST_BUILD
    COMMAND ${PROJECT_SOURCE_DIR}/tests/vcore/certificate-generator/create_certs.sh
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/tests/vcore/certificate-generator/
    COMMENT "Generate certificate chains"
    )

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget/author-signature.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget/signature1.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget/signature22.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget/config.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget/index.html
    DESTINATION
    /opt/apps/widget/tests/vcore_widget_uncompressed
    )

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_negative_hash/author-signature.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_negative_hash/signature1.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_negative_hash/signature22.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_negative_hash/config.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_negative_hash/index.html
    DESTINATION
    /opt/apps/widget/tests/vcore_widget_uncompressed_negative_hash
    )

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_negative_signature/author-signature.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_negative_signature/signature1.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_negative_signature/signature22.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_negative_signature/config.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_negative_signature/index.html
    DESTINATION
    /opt/apps/widget/tests/vcore_widget_uncompressed_negative_signature
    )

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_negative_certificate/author-signature.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_negative_certificate/signature1.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_negative_certificate/config.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_negative_certificate/index.html
    DESTINATION
    /opt/apps/widget/tests/vcore_widget_uncompressed_negative_certificate
    )

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_partner/author-signature.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_partner/signature1.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_partner/config.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_partner/index.html
    DESTINATION
    /opt/apps/widget/tests/vcore_widget_uncompressed_partner
    )

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_partner_operator/author-signature.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_partner_operator/signature1.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_partner_operator/config.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/widget_partner_operator/index.html
    DESTINATION
    /opt/apps/widget/tests/vcore_widget_uncompressed_partner_operator
    )

INSTALL(FILES
    "${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/reference/encoding test.empty"
    DESTINATION
    /opt/apps/widget/tests/reference
    )

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/keys/operator.root.cert.pem
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/keys/root_cacert0.pem
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/keys/CAbundle.crt
    DESTINATION
    /opt/apps/widget/tests/vcore_keys
    )

IF(DEFINED TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)
INSTALL(FILES
	${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/keys/ocsp_level0deprecated.crt
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/keys/ocsp_level1.crt
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/keys/ocsp_level2.crt
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/keys/ocsp_rootca.crt
	DESTINATION
    /opt/apps/widget/tests/vcore_keys
    )
ENDIF(DEFINED TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/config/fin_list.xml
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/config/fin_list.xsd
    DESTINATION
    /opt/apps/widget/tests/vcore_config/
)

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/tests/vcore/test-cases/keys/root_cacert0.pem
    DESTINATION
    /usr/share/cert-svc/certs/code-signing/wac
    )

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/tests/vcore/certificate-generator/demoCA/cacert.pem
    ${PROJECT_SOURCE_DIR}/tests/vcore/certificate-generator/1second_level.pem
    ${PROJECT_SOURCE_DIR}/tests/vcore/certificate-generator/1third_level.pem
    ${PROJECT_SOURCE_DIR}/tests/vcore/certificate-generator/2second_level.pem
    ${PROJECT_SOURCE_DIR}/tests/vcore/certificate-generator/2third_level.pem
    ${PROJECT_SOURCE_DIR}/tests/vcore/certificate-generator/3second_level.pem
    ${PROJECT_SOURCE_DIR}/tests/vcore/certificate-generator/3third_level.pem
    ${PROJECT_SOURCE_DIR}/tests/vcore/certificate-generator/respcert.pem
    ${PROJECT_SOURCE_DIR}/tests/vcore/certificate-generator/respcert.key
    ${PROJECT_SOURCE_DIR}/tests/vcore/certificate-generator/openssl.cnf
    DESTINATION
    /opt/apps/widget/tests/vcore_certs/
)

IF(DEFINED TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)
INSTALL(FILES
	${PROJECT_SOURCE_DIR}/tests/vcore/certificate-generator/cacrl1.pem
    ${PROJECT_SOURCE_DIR}/tests/vcore/certificate-generator/cacrl2.pem
	DESTINATION
    /opt/apps/widget/tests/vcore_certs/
	)
ENDIF(DEFINED TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)

INSTALL(DIRECTORY
    ${PROJECT_SOURCE_DIR}/tests/vcore/certificate-generator/demoCA
    DESTINATION
    /opt/apps/widget/tests/vcore_certs/
)

