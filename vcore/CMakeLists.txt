#DB vcore
PKG_CHECK_MODULES(VCORE_DB_DEP
    dpl-efl
    REQUIRED)

ADD_CUSTOM_COMMAND(
    OUTPUT ${CMAKE_BINARY_DIR}/vcore/src/database_checksum_vcore.h
    COMMAND ${CMAKE_SOURCE_DIR}/vcore/src/orm/gen_db_md5.sh
    ARGS ${CMAKE_BINARY_DIR}/vcore/src/database_checksum_vcore.h
         ${CMAKE_SOURCE_DIR}/vcore/src/orm/vcore_db
    DEPENDS ${CMAKE_SOURCE_DIR}/vcore/src/orm/vcore_db
            ${CMAKE_SOURCE_DIR}/vcore/src/orm/gen_db_md5.sh
    COMMENT "Generating VCORE database checksum"
    )

STRING(REPLACE ";" ":" DEPENDENCIES "${VCORE_DB_DEP_INCLUDE_DIRS}")

ADD_CUSTOM_COMMAND( OUTPUT .cert_svc_vcore.db
  COMMAND rm -f ${CMAKE_CURRENT_BINARY_DIR}/.cert_svc_vcore.db
  COMMAND CPATH=${DEPENDENCIES} gcc -Wall -include ${CMAKE_BINARY_DIR}/vcore/src/database_checksum_vcore.h -I${PROJECT_SOURCE_DIR}/vcore/src/orm -E ${PROJECT_SOURCE_DIR}/vcore/src/orm/vcore_db_sql_generator.h | grep --invert-match "^#" > ${CMAKE_CURRENT_BINARY_DIR}/cert_svc_vcore_db.sql
  COMMAND sqlite3 ${CMAKE_CURRENT_BINARY_DIR}/.cert_svc_vcore.db ".read ${CMAKE_CURRENT_BINARY_DIR}/cert_svc_vcore_db.sql" || rm -f ${CMAKE_CURRENT_BINARY_DIR}/.cert_svc_vcore.db
  DEPENDS ${CMAKE_BINARY_DIR}/vcore/src/database_checksum_vcore.h ${PROJECT_SOURCE_DIR}/vcore/src/orm/vcore_db_sql_generator.h ${PROJECT_SOURCE_DIR}/vcore/src/orm/vcore_db
  )

ADD_CUSTOM_COMMAND( OUTPUT .cert_svc_vcore.db-journal
  COMMAND touch
  ARGS  ${CMAKE_CURRENT_BINARY_DIR}/.cert_svc_vcore.db-journal
  )

ADD_CUSTOM_TARGET(Sqlite3DbVCORE ALL DEPENDS .cert_svc_vcore.db .cert_svc_vcore.db-journal)

INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/cert_svc_vcore_db.sql
    DESTINATION /usr/share/cert-svc/
    )

ADD_SUBDIRECTORY(src)
