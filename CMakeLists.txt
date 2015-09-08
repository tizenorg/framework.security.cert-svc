CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(certsvc)

INCLUDE(FindPkgConfig)

SET(SO_VERSION 1)
SET(VERSION "${SO_VERSION}.0.0")

SET(TARGET_CERT_SVC_LIB "cert-svc")
SET(TARGET_VCORE_LIB "cert-svc-vcore")

# compiler options
SET(GC_SECTIONS_FLAGS "-fdata-sections -ffunction-sections -Wl,--gc-sections")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GC_SECTIONS_FLAGS}")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GC_SECTIONS_FLAGS}")

SET(CMAKE_C_FLAGS_RELEASE "-fvisibility=hidden -Wall -O2")
SET(CMAKE_CXX_FLAGS_RELEASE "-std=c++0x -Wall -O2")

SET(CMAKE_C_FLAGS_DEBUG "-fvisibility=hidden -Wall -O0 -g")
SET(CMAKE_CXX_FLAGS_DEBUG "-std=c++0x -Wall -O0 -g")

SET(CMAKE_C_FLAGS_CCOV "-fvisibility=hidden -Wall -O2 --coverage")
SET(CMAKE_CXX_FLAGS_CCOV "-std=c++0x -Wall -O2 --coverage")

SET(CMAKE_SHARED_LINKER_FLAGS "-Wl,--as-needed")
SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed")
SET(CMAKE_SKIP_RPATH "TRUE")
#SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wmissing-declarations")

################################################################################
# for libcert-svc.so
################################################################################

PKG_CHECK_MODULES(CERT_SVC_DEPS
    REQUIRED
    openssl
    dlog
    glib-2.0
    libxml-2.0
)

SET(CERT_SVC_SOURCES
    ${PROJECT_SOURCE_DIR}/srcs/cert-service.c
    ${PROJECT_SOURCE_DIR}/srcs/cert-service-util.c
    ${PROJECT_SOURCE_DIR}/srcs/cert-service-store.c
    ${PROJECT_SOURCE_DIR}/srcs/cert-service-process.c
)

IF (CMAKE_BUILD_TYPE MATCHES "DEBUG")
    ADD_DEFINITIONS("-DTIZEN_DEBUG_ENABLE")
    ADD_DEFINITIONS("-DBUILD_TYPE_DEBUG")
ENDIF (CMAKE_BUILD_TYPE MATCHES "DEBUG")

INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/include
    ${CERT_SVC_DEPS_INCLUDE_DIRS}
)

ADD_DEFINITIONS("-DDPL_LOGS_ENABLED")

IF(DEFINED TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)
MESSAGE("TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL ENABLED")
ADD_DEFINITIONS("-DTIZEN_FEATURE_CERT_SVC_OCSP_CRL")
ENDIF(DEFINED TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)

ADD_LIBRARY(${TARGET_CERT_SVC_LIB} SHARED ${CERT_SVC_SOURCES})

SET_TARGET_PROPERTIES(${TARGET_CERT_SVC_LIB} PROPERTIES
    SOVERSION ${SO_VERSION}
    VERSION ${VERSION}
)

TARGET_LINK_LIBRARIES(${TARGET_CERT_SVC_LIB}
    pthread
    ${CERT_SVC_DEPS_LIBRARIES}
)


################################################################################

CONFIGURE_FILE(cert-svc.pc.in cert-svc.pc @ONLY)
CONFIGURE_FILE(cert-svc-vcore.pc.in cert-svc-vcore.pc @ONLY)

INSTALL(TARGETS ${TARGET_CERT_SVC_LIB} DESTINATION ${LIBDIR} COMPONENT RuntimeLibraries)
INSTALL(PROGRAMS ${TARGET_SIGN_TOOL} DESTINATION ${BINDIR})
INSTALL(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/cert-svc.pc
    ${CMAKE_CURRENT_BINARY_DIR}/cert-svc-vcore.pc
    DESTINATION ${LIBDIR}/pkgconfig
)
INSTALL(FILES ${PROJECT_SOURCE_DIR}/targetinfo DESTINATION /opt/share/cert-svc/)
INSTALL(FILES ${PROJECT_SOURCE_DIR}/res/pin/.pin DESTINATION /opt/share/cert-svc/pin/)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/cert-service.h DESTINATION ${INCLUDEDIR})
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/res/ca-certificate.crt DESTINATION /opt/share/cert-svc/)

# Now we must create empty directory for certificates.
# Without this directories rpm package will fail during build.
#INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
#    DESTINATION /usr/share/cert-svc/ca-certs/code-signing/native
#    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
#)
#INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
#    DESTINATION /usr/share/cert-svc/ca-certs/code-signing/wac
#    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
#)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION /usr/share/cert-svc/certs/code-signing/wac
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION /usr/share/cert-svc/certs/code-signing/tizen
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
IF(DEFINED TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)
INSTALL(FILES ${PROJECT_SOURCE_DIR}/res/fota/FOTA_ROOT.cer
    DESTINATION /usr/share/cert-svc/certs/fota
)
ENDIF(DEFINED TIZEN_FEAT_PROFILE_CERT_SVC_OCSP_CRL)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION /opt/share/cert-svc/certs/sim/operator
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION /opt/share/cert-svc/certs/sim/thirdparty
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION /opt/share/cert-svc/certs/user
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION /opt/share/cert-svc/certs/trusteduser
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION /opt/share/cert-svc/certs/mdm/security
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION /opt/share/cert-svc/certs/mdm/security/cert
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION /opt/share/cert-svc/pkcs12
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)

ADD_SUBDIRECTORY(vcore)
ADD_SUBDIRECTORY(etc)
IF (DEFINED CERTSVC_BUILD_TEST_PACKAGE)
ADD_SUBDIRECTORY(tests)
ENDIF (DEFINED CERTSVC_BUILD_TEST_PACKAGE)
