SET(ETC_DIR ${PROJECT_SOURCE_DIR}/etc)

INSTALL(FILES
    ${ETC_DIR}/schema.xsd
    DESTINATION /usr/share/wrt-engine
    )

IF (DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)
INSTALL(FILES
    ${ETC_DIR}/cert_svc_create_clean_db.sh
    DESTINATION /usr/bin
    PERMISSIONS OWNER_READ
                OWNER_WRITE
                OWNER_EXECUTE
    )

INSTALL(FILES
    ${ETC_DIR}/cert_svc_vcore_db.sql
    DESTINATION /usr/share/cert-svc
    )
ENDIF (DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)


IF (DEFINED TIZEN_FEAT_CERTSVC_STORE_CAPABILITY)
INSTALL(FILES
    ${ETC_DIR}/initialize_store_db.sh
    ${ETC_DIR}/cert_svc_create_clean_store_db.sh
    DESTINATION /usr/bin
    PERMISSIONS OWNER_READ
                OWNER_WRITE
                OWNER_EXECUTE
    )

INSTALL(FILES
    ${ETC_DIR}/cert_svc_store_db.sql
    DESTINATION /usr/share/cert-svc
    )
ENDIF (DEFINED TIZEN_FEAT_CERTSVC_STORE_CAPABILITY)

