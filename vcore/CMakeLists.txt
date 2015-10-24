#DB vcore
IF(DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)

ADD_CUSTOM_COMMAND(
    OUTPUT ${CMAKE_BINARY_DIR}/vcore/src/database_checksum_vcore.h
    COMMAND ${CMAKE_SOURCE_DIR}/vcore/src/orm/gen_db_md5.sh
    ARGS ${CMAKE_BINARY_DIR}/vcore/src/database_checksum_vcore.h
         ${CMAKE_SOURCE_DIR}/vcore/src/orm/vcore_db
    DEPENDS ${CMAKE_SOURCE_DIR}/vcore/src/orm/vcore_db
            ${CMAKE_SOURCE_DIR}/vcore/src/orm/gen_db_md5.sh
    COMMENT "Generating VCORE database checksum"
    )

ADD_CUSTOM_COMMAND( OUTPUT .cert_svc_vcore.db
  COMMAND rm -f ${CMAKE_CURRENT_BINARY_DIR}/.cert_svc_vcore.db
  COMMAND CPATH=${DEPENDENCIES} gcc -Wall -include ${CMAKE_BINARY_DIR}/vcore/src/database_checksum_vcore.h -I${PROJECT_SOURCE_DIR}/vcore/src/orm -I${PROJECT_SOURCE_DIR}/vcore/src/dpl/db/include -E ${PROJECT_SOURCE_DIR}/vcore/src/orm/vcore_db_sql_generator.h | grep --invert-match "^#" > ${PROJECT_SOURCE_DIR}/etc/cert_svc_vcore_db.sql
  COMMAND sqlite3 ${CMAKE_CURRENT_BINARY_DIR}/.cert_svc_vcore.db ".read ${PROJECT_SOURCE_DIR}/etc/cert_svc_vcore_db.sql" || rm -f ${CMAKE_CURRENT_BINARY_DIR}/.cert_svc_vcore.db
  DEPENDS ${CMAKE_BINARY_DIR}/vcore/src/database_checksum_vcore.h ${PROJECT_SOURCE_DIR}/vcore/src/orm/vcore_db_sql_generator.h ${PROJECT_SOURCE_DIR}/vcore/src/orm/vcore_db
  )

ADD_CUSTOM_COMMAND( OUTPUT .cert_svc_vcore.db-journal
  COMMAND touch
  ARGS  ${CMAKE_CURRENT_BINARY_DIR}/.cert_svc_vcore.db-journal
  )

ADD_CUSTOM_TARGET(Sqlite3DbVCORE ALL DEPENDS .cert_svc_vcore.db .cert_svc_vcore.db-journal)

ENDIF(DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)

ADD_SUBDIRECTORY(src)
