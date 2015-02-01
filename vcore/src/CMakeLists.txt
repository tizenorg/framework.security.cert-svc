INCLUDE(FindPkgConfig)

PKG_CHECK_MODULES(VCORE_DEPS
    dpl-efl
    ecore
    appcore-efl
    libxml-2.0
    libsoup-2.4
    libpcre
    libpcrecpp
    openssl
    xmlsec1
    secure-storage
    cryptsvc
    REQUIRED)

IF(TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)
PKG_CHECK_MODULES(VCORE_DEPS
    dpl-db-efl
	)
ENDIF()

IF(_WEARABLE)
ADD_DEFINITIONS("-D_WEARABLE")
ENDIF()

IF(_MOBILE)
ADD_DEFINITIONS("-D_MOBILE")
ENDIF()

IF(TIZEN_FEAT_OSP_DISABLE EQUAL 1)
ADD_DEFINITIONS("-DTIZENUCT_FEATURE_OSP_DISABLE")
ENDIF()

SET(LIBCRYPTSVC_DIR
    ${PROJECT_SOURCE_DIR}/vcore
    )

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/include)

SET(VCORE_DIR
    ${PROJECT_SOURCE_DIR}/vcore
    )

SET(VCORE_SRC_DIR
    ${VCORE_DIR}/src/vcore
    )

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
	)
	
IF(TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)
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
    ${VCORE_SRC_DIR}/SignatureFinder.cpp
    ${VCORE_SRC_DIR}/SignatureReader.cpp
    ${VCORE_SRC_DIR}/TimeConversion.cpp
    ${VCORE_SRC_DIR}/VerificationStatus.cpp
    ${VCORE_SRC_DIR}/ValidatorFactories.cpp
    ${VCORE_SRC_DIR}/VCore.cpp
    ${VCORE_SRC_DIR}/DUID.cpp
    ${VCORE_SRC_DIR}/WrtSignatureValidator.cpp
    ${VCORE_SRC_DIR}/SignatureValidator.cpp
    ${VCORE_SRC_DIR}/XmlsecAdapter.cpp
    ${VCORE_SRC_DIR}/pkcs12.c
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
    ${VCORE_SRC_DIR}/SoupMessageSendAsync.cpp
	${VCORE_SRC_DIR}/OCSPUtil.c
    )
ENDIF()

SET(VCORE_INCLUDES
    ${VCORE_DEPS_INCLUDE_DIRS}
    ${VCORE_SRC_DIR}
    ${VCORE_DIR}/src
IF(TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)
    ${VCORE_DIR}/src/orm
ENDIF()
    ${VCORE_DIR}/src/legacy
    ${CMAKE_BINARY_DIR}/vcore/src
    )

ADD_DEFINITIONS(${VCORE_DEPS_CFLAGS})
ADD_DEFINITIONS(${VCORE_DEPS_CFLAGS_OTHER})
ADD_DEFINITIONS("-DSEPARATED_SINGLETON_IMPLEMENTATION")
ADD_DEFINITIONS("-DDPL_LOGS_ENABLED")
ADD_DEFINITIONS("-DCERT_SVC_LOG")
IF(TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)
ADD_DEFINITIONS("-DTIZENUCT_FEATURE_CERT_SVC_OCSP_CRL")
ENDIF()

INCLUDE_DIRECTORIES(${VCORE_INCLUDES})

# cert-svc headers
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/include)

ADD_LIBRARY(${TARGET_VCORE_LIB} SHARED ${VCORE_SOURCES})
SET_TARGET_PROPERTIES(${TARGET_VCORE_LIB} PROPERTIES
    SOVERSION ${SO_VERSION}
    VERSION ${VERSION})
IF(TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)
ADD_DEPENDENCIES(${TARGET_VCORE_LIB} Sqlite3DbWTF)
ENDIF()

IF(TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)
TARGET_LINK_LIBRARIES(${TARGET_VCORE_LIB}
    ${VCORE_DEPS_LIBRARIES}
    ${TARGET_CERT_SVC_LIB}
    dpl-db-efl
  )
ELSE()
TARGET_LINK_LIBRARIES(${TARGET_VCORE_LIB}
    ${VCORE_DEPS_LIBRARIES}
    ${TARGET_CERT_SVC_LIB}
  )
ENDIF ()
INSTALL(TARGETS ${TARGET_VCORE_LIB}
    DESTINATION ${LIBDIR}
    )

INSTALL(FILES
    ${VCORE_SRC_DIR}/Base64.h
    ${VCORE_SRC_DIR}/Certificate.h
    ${VCORE_SRC_DIR}/CertificateCollection.h
    ${VCORE_SRC_DIR}/CertStoreType.h
    ${VCORE_SRC_DIR}/CryptoHash.h
    ${VCORE_SRC_DIR}/IAbstractResponseCache.h
    ${VCORE_SRC_DIR}/ParserSchema.h
    ${VCORE_SRC_DIR}/ReferenceValidator.h
    ${VCORE_SRC_DIR}/SaxReader.h
    ${VCORE_SRC_DIR}/SignatureData.h
    ${VCORE_SRC_DIR}/SignatureFinder.h
    ${VCORE_SRC_DIR}/SignatureReader.h
    ${VCORE_SRC_DIR}/WrtSignatureValidator.h
    ${VCORE_SRC_DIR}/SignatureValidator.h
    ${VCORE_SRC_DIR}/VerificationStatus.h
    ${VCORE_SRC_DIR}/VCore.h
    DESTINATION ${INCLUDEDIR}/cert-svc/vcore
    )

IF(TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)
INSTALL(FILES
	${VCORE_SRC_DIR}/CachedCRL.h
    ${VCORE_SRC_DIR}/CachedOCSP.h
	${VCORE_SRC_DIR}/CRL.h
    ${VCORE_SRC_DIR}/CRLCacheInterface.h
	${VCORE_SRC_DIR}/OCSP.h
    ${VCORE_SRC_DIR}/OCSPCertMgrUtil.h
	DESTINATION ${INCLUDEDIR}/cert-svc/vcore
	)
ENDIF()

INSTALL(FILES
    ${VCORE_DIR}/src/cert-svc/ccert.h
    ${VCORE_DIR}/src/cert-svc/cinstance.h
    ${VCORE_DIR}/src/cert-svc/cerror.h
    ${VCORE_DIR}/src/cert-svc/cpkcs12.h
    ${VCORE_DIR}/src/cert-svc/cprimitives.h
    ${VCORE_DIR}/src/cert-svc/cstring.h
    DESTINATION ${INCLUDEDIR}/cert-svc/cert-svc
    )

IF(TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)
INSTALL(FILES
	${VCORE_DIR}/src/cert-svc/ccrl.h
	${VCORE_DIR}/src/cert-svc/cocsp.h
	DESTINATION ${INCLUDEDIR}/cert-svc/cert-svc
	)
ENDIF()

#FILE(MAKE_DIRECTORY /opt/share/cert-svc/pkcs12)
