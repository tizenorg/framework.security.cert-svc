SET(ETC_DIR ${PROJECT_SOURCE_DIR}/etc)

INSTALL(FILES
    ${ETC_DIR}/cert_svc_create_clean_db.sh
    DESTINATION /usr/bin
    )
