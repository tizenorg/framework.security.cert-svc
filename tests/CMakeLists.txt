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

IF(DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)
PKG_CHECK_MODULES(VCORE_TEST_DEP
    REQUIRED
    libpcrecpp
    icu-uc
    secure-storage
    dlog
    glib-2.0
    libsoup-2.4
    db-util

    sqlite3
    )
ELSE(DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)
PKG_CHECK_MODULES(VCORE_TEST_DEP
    REQUIRED
    libpcrecpp
    icu-uc
    secure-storage
    dlog
    glib-2.0
    libsoup-2.4
    db-util
    )
ENDIF(DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)

SET(VCORE_DPL_DIR
    ${PROJECT_SOURCE_DIR}/vcore/src/dpl
    )

SET(VCORE_DPL_CORE_SRC_DIR
    ${VCORE_DPL_DIR}/core/src
    )
SET(VCORE_DPL_CORE_SOURCES
    ${VCORE_DPL_CORE_SRC_DIR}/assert.cpp
    ${VCORE_DPL_CORE_SRC_DIR}/binary_queue.cpp
    ${VCORE_DPL_CORE_SRC_DIR}/char_traits.cpp
    ${VCORE_DPL_CORE_SRC_DIR}/colors.cpp
    ${VCORE_DPL_CORE_SRC_DIR}/errno_string.cpp
    ${VCORE_DPL_CORE_SRC_DIR}/exception.cpp
    ${VCORE_DPL_CORE_SRC_DIR}/file_input.cpp
    ${VCORE_DPL_CORE_SRC_DIR}/noncopyable.cpp
    ${VCORE_DPL_CORE_SRC_DIR}/singleton.cpp
    ${VCORE_DPL_CORE_SRC_DIR}/string.cpp
    ${VCORE_DPL_CORE_SRC_DIR}/type_list.cpp
    ${VCORE_DPL_CORE_SRC_DIR}/thread.cpp
    ${VCORE_DPL_CORE_SRC_DIR}/waitable_event.cpp
    ${VCORE_DPL_CORE_SRC_DIR}/waitable_handle.cpp
    ${VCORE_DPL_CORE_SRC_DIR}/waitable_handle_watch_support.cpp
    )

SET(VCORE_DPL_DB_SRC_DIR
    ${VCORE_DPL_DIR}/db/src
    )
SET(VCORE_DPL_DB_SOURCES
    ${VCORE_DPL_DB_SRC_DIR}/naive_synchronization_object.cpp
    ${VCORE_DPL_DB_SRC_DIR}/orm.cpp
    ${VCORE_DPL_DB_SRC_DIR}/sql_connection.cpp
    ${VCORE_DPL_DB_SRC_DIR}/thread_database_support.cpp
    )

SET(VCORE_DPL_LOG_SRC_DIR
    ${VCORE_DPL_DIR}/log/src
    )
SET(VCORE_DPL_LOG_SOURCES
    ${VCORE_DPL_LOG_SRC_DIR}/abstract_log_provider.cpp
    ${VCORE_DPL_LOG_SRC_DIR}/dlog_log_provider.cpp
    ${VCORE_DPL_LOG_SRC_DIR}/log.cpp
    ${VCORE_DPL_LOG_SRC_DIR}/old_style_log_provider.cpp
    )

SET(VCORE_DPL_TEST_SRC_DIR
    ${VCORE_DPL_DIR}/test/src
    )
SET(VCORE_DPL_TEST_SOURCES
    ${VCORE_DPL_TEST_SRC_DIR}/process_pipe.cpp
    ${VCORE_DPL_TEST_SRC_DIR}/test_results_collector.cpp
    ${VCORE_DPL_TEST_SRC_DIR}/test_runner_child.cpp
    ${VCORE_DPL_TEST_SRC_DIR}/test_runner.cpp
    ${VCORE_DPL_TEST_SRC_DIR}/test_runner_multiprocess.cpp
    ${VCORE_DPL_TEST_SRC_DIR}/value_separated_policies.cpp
    ${VCORE_DPL_TEST_SRC_DIR}/value_separated_tokens.cpp
    )


IF(DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)
SET(VCORE_DPL_SOURCES
    ${VCORE_DPL_CORE_SOURCES}
    ${VCORE_DPL_DB_SOURCES}
    ${VCORE_DPL_LOG_SOURCES}
    ${VCORE_DPL_TEST_SOURCES}
    )
SET(VCORE_DPL_INCLUDE
    ${VCORE_DPL_DIR}/core/include
    ${VCORE_DPL_DIR}/db/include
    ${VCORE_DPL_DIR}/log/include
    ${VCORE_DPL_DIR}/test/include
    )
ELSE(DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)
SET(VCORE_DPL_SOURCES
    ${VCORE_DPL_CORE_SOURCES}
    ${VCORE_DPL_LOG_SOURCES}
    ${VCORE_DPL_TEST_SOURCES}
    )
SET(VCORE_DPL_INCLUDE
    ${VCORE_DPL_DIR}/core/include
    ${VCORE_DPL_DIR}/log/include
    ${VCORE_DPL_DIR}/test/include
    )
ENDIF(DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)

INCLUDE_DIRECTORIES(
    SYSTEM
    ${VCORE_TEST_DEP_INCLUDE_DIRS}
    ${VCORE_DPL_INCLUDE}
    ${PROJECT_SOURCE_DIR}/include
    )

ADD_SUBDIRECTORY(capi)
ADD_SUBDIRECTORY(pkcs12)
ADD_SUBDIRECTORY(vcore)
ADD_SUBDIRECTORY(cert-svc)
ADD_SUBDIRECTORY(verify-signature-tpk)
