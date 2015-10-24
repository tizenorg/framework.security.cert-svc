INSTALL(
	FILES
		${PROJECT_SOURCE_DIR}/systemd/cert-server.socket
		${PROJECT_SOURCE_DIR}/systemd/cert-server.service
	DESTINATION ${SYSTEMD_UNIT_DIR}
	)
