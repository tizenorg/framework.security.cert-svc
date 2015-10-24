# compiler warning flags
ADD_DEFINITIONS("-Wall")
ADD_DEFINITIONS("-Wextra")
ADD_DEFINITIONS("-Werror")

IF(DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)
PKG_CHECK_MODULES(VCORE_DEPS
    REQUIRED
    glib-2.0
    libxml-2.0
    libpcrecpp
    openssl
    xmlsec1
    dlog
    secure-storage
    icu-uc
    libsoup-2.4
    db-util

    sqlite3
    vconf
    )
ELSE(DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)
PKG_CHECK_MODULES(VCORE_DEPS
    REQUIRED
    glib-2.0
    libxml-2.0
    libpcrecpp
    openssl
    xmlsec1
    dlog
    secure-storage
    icu-uc
    libsoup-2.4
    db-util
    )
ENDIF(DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)

ADD_DEFINITIONS(${VCORE_DEPS_CFLAGS})
ADD_DEFINITIONS(${VCORE_DEPS_CFLAGS_OTHER})
ADD_DEFINITIONS("-DSEPARATED_SINGLETON_IMPLEMENTATION")

SET(VCORE_DIR
    ${PROJECT_SOURCE_DIR}/vcore
    )

SET(VCORE_SRC_DIR
    ${VCORE_DIR}/src/vcore
    )

########### DPL SOURCES ##########
SET(VCORE_DPL_DIR
    ${VCORE_DIR}/src/dpl
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
########### DPL SOURCES ##########


########### VCORE SOURCES ########
SET(VCORE_SOURCES
    ${VCORE_SRC_DIR}/api.cpp
    ${VCORE_SRC_DIR}/Base64.cpp
    ${VCORE_SRC_DIR}/Certificate.cpp
    ${VCORE_SRC_DIR}/CertificateCollection.cpp
    ${VCORE_SRC_DIR}/CertificateConfigReader.cpp
    ${VCORE_SRC_DIR}/CertificateLoader.cpp
    ${VCORE_SRC_DIR}/CertStoreType.cpp
    ${VCORE_SRC_DIR}/Config.cpp
    ${VCORE_SRC_DIR}/CryptoHash.cpp
    ${VCORE_SRC_DIR}/OCSPCertMgrUtil.cpp
    ${VCORE_SRC_DIR}/ReferenceValidator.cpp
    ${VCORE_SRC_DIR}/RevocationCheckerBase.cpp
    ${VCORE_SRC_DIR}/SaxReader.cpp
    ${VCORE_SRC_DIR}/SignatureData.cpp
    ${VCORE_SRC_DIR}/SignatureFinder.cpp
    ${VCORE_SRC_DIR}/SignatureReader.cpp
    ${VCORE_SRC_DIR}/TimeConversion.cpp
    ${VCORE_SRC_DIR}/VerificationStatus.cpp
    ${VCORE_SRC_DIR}/ValidatorFactories.cpp
    ${VCORE_SRC_DIR}/VCore.cpp
    ${VCORE_SRC_DIR}/WrtSignatureValidator.cpp
    ${VCORE_SRC_DIR}/SignatureValidator.cpp
    ${VCORE_SRC_DIR}/XmlsecAdapter.cpp
    ${VCORE_SRC_DIR}/pkcs12.c
    ${VCORE_SRC_DIR}/exception.cpp

    ${VCORE_SRC_DIR}/cert-svc-client.c
    ${VCORE_SRC_DIR}/CachedRootCerts.c
    )

SET(VCORE_OCSP_CRL_SOURCES
    ${VCORE_SRC_DIR}/CachedCRL.cpp
    ${VCORE_SRC_DIR}/CachedOCSP.cpp
    ${VCORE_SRC_DIR}/CertificateCacheDAO.cpp
    ${VCORE_SRC_DIR}/CertificateVerifier.cpp
    ${VCORE_SRC_DIR}/CRL.cpp
    ${VCORE_SRC_DIR}/CRLImpl.cpp
    ${VCORE_SRC_DIR}/CRLCacheDAO.cpp
    ${VCORE_SRC_DIR}/Database.cpp
    ${VCORE_SRC_DIR}/OCSP.cpp
    ${VCORE_SRC_DIR}/OCSPImpl.cpp
    ${VCORE_SRC_DIR}/SoupMessageSendBase.cpp
    ${VCORE_SRC_DIR}/SoupMessageSendSync.cpp
    ${VCORE_SRC_DIR}/OCSPUtil.c
    )

SET(VCORE_INCLUDES
    ${VCORE_DEPS_INCLUDE_DIRS}
    ${VCORE_SRC_DIR}
    ${VCORE_DIR}/src
    ${VCORE_DIR}/src/legacy
    )

SET(VCORE_INCLUDES_OCSP_CRL
    ${VCORE_DIR}/src/orm
    )
########### VCORE SOURCES ########

IF(DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)
SET(VCORE_ALL_SOURCES
    ${VCORE_SOURCES}
    ${VCORE_DPL_CORE_SOURCES}
    ${VCORE_DPL_DB_SOURCES}
    ${VCORE_DPL_LOG_SOURCES}
    ${VCORE_OCSP_CRL_SOURCES}
    )
SET(VCORE_ALL_INCLUDES
    ${PROJECT_SOURCE_DIR}/include
    ${VCORE_INCLUDES}
    ${VCORE_DPL_DIR}/core/include
    ${VCORE_DPL_DIR}/db/include
    ${VCORE_DPL_DIR}/log/include
    ${VCORE_INCLUDES_OCSP_CRL}
    )
ELSE(DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)
SET(VCORE_ALL_SOURCES
    ${VCORE_SOURCES}
    ${VCORE_DPL_CORE_SOURCES}
    ${VCORE_DPL_LOG_SOURCES}
    )
SET(VCORE_ALL_INCLUDES
    ${PROJECT_SOURCE_DIR}/include
    ${VCORE_INCLUDES}
    ${VCORE_DPL_DIR}/core/include
    ${VCORE_DPL_DIR}/log/include
    )
ENDIF(DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)

INCLUDE_DIRECTORIES(${VCORE_ALL_INCLUDES})

ADD_LIBRARY(${TARGET_VCORE_LIB} SHARED ${VCORE_ALL_SOURCES})

# TODO: visibility needed to be hidden
SET_TARGET_PROPERTIES(${TARGET_VCORE_LIB}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fPIC -fvisibility=default"
        SOVERSION ${SO_VERSION}
        VERSION ${VERSION})

IF(DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)
ADD_DEPENDENCIES(${TARGET_VCORE_LIB} Sqlite3DbWTF)
ENDIF(DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)

TARGET_LINK_LIBRARIES(${TARGET_VCORE_LIB}
    ${VCORE_DEPS_LIBRARIES}
    ${TARGET_CERT_SVC_LIB}
    )

########## cert-server #############
PKG_CHECK_MODULES(CERT_SERVER_DEP
    REQUIRED
    dlog
    sqlite3
    db-util
    libsystemd-daemon
    key-manager
    )

SET(CERT_SERVER_DIR
    ${PROJECT_SOURCE_DIR}/vcore/src/server
    )

SET(CERT_SERVER_SRCS
    ${CERT_SERVER_DIR}/src/cert-server-main.c
    ${CERT_SERVER_DIR}/src/cert-server-logic.c
    )

INCLUDE_DIRECTORIES(
    SYSTEM
    ${CERT_SERVER_DEP_INCLUDE_DIRS}
    ${PROJECT_SOURCE_DIR}/include
    ${VCORE_DIR}/src
    ${CERT_SERVER_DIR}/include
    )

SET_SOURCE_FILES_PROPERTIES(
    ${CERT_SERVER_SRCS}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fvisibility=hidden -fPIE"
    )

ADD_EXECUTABLE(${TARGET_CERT_SERVER} ${CERT_SERVER_SRCS})

TARGET_LINK_LIBRARIES(${TARGET_CERT_SERVER}
    ${CERT_SERVER_DEP_LIBRARIES}
    -pie
    )

INSTALL(TARGETS ${TARGET_CERT_SERVER} DESTINATION ${BINDIR})

########################################################
INSTALL(TARGETS ${TARGET_VCORE_LIB}
    DESTINATION ${LIBDIR}
    )

INSTALL(FILES
    ${VCORE_SRC_DIR}/VCore.h
    ${VCORE_SRC_DIR}/WrtSignatureValidator.h
    ${VCORE_SRC_DIR}/SignatureValidator.h
    ${VCORE_SRC_DIR}/SignatureFinder.h
    ${VCORE_SRC_DIR}/SignatureReader.h
    ${VCORE_SRC_DIR}/CertificateCollection.h
    ${VCORE_SRC_DIR}/CryptoHash.h

    ${VCORE_SRC_DIR}/ParserSchema.h
    ${VCORE_SRC_DIR}/SaxReader.h

    ${VCORE_SRC_DIR}/Certificate.h
    ${VCORE_SRC_DIR}/SignatureData.h
    ${VCORE_SRC_DIR}/CertStoreType.h
    ${VCORE_SRC_DIR}/exception.h
    DESTINATION ${INCLUDEDIR}/cert-svc/vcore
    )

INSTALL(FILES
    ${VCORE_DIR}/src/cert-svc/ccert.h
    ${VCORE_DIR}/src/cert-svc/cinstance.h
    ${VCORE_DIR}/src/cert-svc/cerror.h
    ${VCORE_DIR}/src/cert-svc/cpkcs12.h
    ${VCORE_DIR}/src/cert-svc/cprimitives.h
    ${VCORE_DIR}/src/cert-svc/cstring.h
    DESTINATION ${INCLUDEDIR}/cert-svc/cert-svc
    )

IF(DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)
INSTALL(FILES
    ${VCORE_SRC_DIR}/IAbstractResponseCache.h
    ${VCORE_SRC_DIR}/VerificationStatus.h
    ${VCORE_SRC_DIR}/CachedCRL.h
    ${VCORE_SRC_DIR}/CachedOCSP.h
    ${VCORE_SRC_DIR}/CRL.h
    ${VCORE_SRC_DIR}/CRLCacheInterface.h
    ${VCORE_SRC_DIR}/OCSP.h
    ${VCORE_SRC_DIR}/OCSPCertMgrUtil.h
    DESTINATION ${INCLUDEDIR}/cert-svc/vcore
    )

INSTALL(FILES
    ${VCORE_DIR}/src/cert-svc/ccrl.h
    ${VCORE_DIR}/src/cert-svc/cocsp.h
    DESTINATION ${INCLUDEDIR}/cert-svc/cert-svc
    )
ENDIF(DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)

#FILE(MAKE_DIRECTORY /opt/share/cert-svc/pkcs12)
