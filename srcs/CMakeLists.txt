# compiler warning flags
ADD_DEFINITIONS("-Wall")
ADD_DEFINITIONS("-Wextra")
ADD_DEFINITIONS("-Werror")

PKG_CHECK_MODULES(CERT_SVC_DEP
    REQUIRED
    openssl
    dlog
    glib-2.0
    libxml-2.0
    xmlsec1
    secure-storage
    )

SET(CERT_SVC_PATH ${CMAKE_CURRENT_SOURCE_DIR})

SET(CERT_SVC_SOURCES
    ${CERT_SVC_PATH}/cert-service.c
    ${CERT_SVC_PATH}/cert-service-util.c
    ${CERT_SVC_PATH}/cert-service-store.c
    ${CERT_SVC_PATH}/cert-service-process.c
    )

INCLUDE_DIRECTORIES(
    SYSTEM
    ${CERT_SVC_DEP_INCLUDE_DIRS}
    ${PROJECT_SOURCE_DIR}/include
    )

ADD_LIBRARY(${TARGET_CERT_SVC_LIB} SHARED ${CERT_SVC_SOURCES})

SET_TARGET_PROPERTIES(
    ${TARGET_CERT_SVC_LIB}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fPIC -fvisibility=hidden"
        SOVERSION ${SO_VERSION}
        VERSION ${VERSION}
    )

TARGET_LINK_LIBRARIES(${TARGET_CERT_SVC_LIB}
    ${CERT_SVC_DEP_LIBRARIES}
    )

INSTALL(TARGETS ${TARGET_CERT_SVC_LIB} DESTINATION ${LIBDIR})
