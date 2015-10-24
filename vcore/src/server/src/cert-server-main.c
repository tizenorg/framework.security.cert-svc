/**
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
/**
 * @file     cert-server-main.c
 * @author   Madhan A K (madhan.ak@samsung.com)
 *           Kyungwook Tak (k.tak@samsung.com)
 * @version  1.0
 * @brief    cert-svc server.
 */

#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <systemd/sd-daemon.h>

#include <cert-service-debug.h>
#include <cert-svc/cerror.h>
#include <cert-svc/ccert.h>
#include <cert-svc-client.h>

#include <cert-server-logic.h>

sqlite3 *cert_store_db = NULL;

int open_db(sqlite3 **db_handle, const char *db_path) {

	int result = CERTSVC_FAIL;
	sqlite3 *handle;

	if (access(db_path, F_OK) == 0) {
		result = db_util_open(db_path, &handle, 0);
		if (result != SQLITE_OK) {
			SLOGE("connect db [%s] failed!", db_path);
			return CERTSVC_FAIL;
		}
		*db_handle = handle;
		return CERTSVC_SUCCESS;
	}
	SLOGD("%s DB does not exists. Creating one!!", db_path);

	result = db_util_open(db_path, &handle, 0);
	if (result != SQLITE_OK) {
		SLOGE("connect to db [%s] failed!.", db_path);
		return CERTSVC_FAIL;
	}
	*db_handle = handle;
	return CERTSVC_SUCCESS;
}

int evaluate_query(sqlite3 *db_handle, char *query) {

	int result = CERTSVC_SUCCESS;
	sqlite3_stmt* p_statement;

	if (!db_handle) {
		SLOGE("Database not initialised.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	if (!query) {
		SLOGE("Query is NULL.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	result = sqlite3_prepare_v2(db_handle, query, strlen(query), &p_statement, NULL);
	if (result != SQLITE_OK) {
		SLOGE("Sqlite3 error [%d] : <%s> preparing <%s> query.", result, sqlite3_errmsg(db_handle), query);
		return CERTSVC_FAIL;
	}

	result = sqlite3_step(p_statement);
	if (result != SQLITE_DONE) {
		SLOGE("Sqlite3 error [%d] : <%s> executing <%s> statement.", result, sqlite3_errmsg(db_handle), query);
		return CERTSVC_FAIL;
	}

	result = sqlite3_finalize(p_statement);
	if (result != SQLITE_OK) {
		SLOGE("Sqlite3 error [%d] : <%s> finalising <%s> statement.", result, sqlite3_errmsg(db_handle), query);
		return CERTSVC_FAIL;
	}
	return CERTSVC_SUCCESS;
}

int initialize_db(void) {

	int result = CERTSVC_SUCCESS;

	if (cert_store_db != NULL)
		return CERTSVC_SUCCESS;

	result = open_db(&cert_store_db, CERTSVC_SYSTEM_STORE_DB);
	if (result != CERTSVC_SUCCESS)
		SLOGE("Certsvc store DB creation failed. ret : %d", result);

	return result;
}

void CertSigHandler(int signo)
{
	SLOGD("Got Signal %d, exiting now.", signo);
	if (cert_store_db != NULL) {
		sqlite3_close(cert_store_db);
		cert_store_db = NULL;
	}
	exit(1);
}

int CertSvcGetSocketFromSystemd(int* pSockfd)
{
	int n = sd_listen_fds(0);
	int fd;

	for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START+n; ++fd) {
		if (0 < sd_is_socket_unix(fd, SOCK_STREAM, 1, VCORE_SOCK_PATH, 0)) {
			LOGD("Get socket from systemd. fd[%d]", fd);
			*pSockfd = fd;
			return CERTSVC_SUCCESS;
		}
	}
	return CERTSVC_FAIL;
}

void CertSvcServerComm()
{
	int server_sockfd = 0;
	int client_sockfd = 0;
	int read_len = 0;
	int client_len = 0;
	struct sockaddr_un clientaddr;
	int result = CERTSVC_SUCCESS;
	char *certListBuffer = NULL;
	char *certBlockBuffer = NULL;
	size_t bufferLen = 0;
	size_t blockBufferLen = 0;

	struct timeval timeout;
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;

	SLOGI("cert-server is starting...");

	VcoreRequestData recv_data;
	VcoreResponseData send_data;

	if (!CertSvcGetSocketFromSystemd(&server_sockfd)) {
		SLOGE("Failed to get sockfd from systemd.");
		return;
	}

	client_len = sizeof(clientaddr);
	signal(SIGINT, (void*)CertSigHandler);

	result = initialize_db();
	if (result != CERTSVC_SUCCESS) {
		SLOGE("Failed to initialize database. ret : %d", result);
		result = CERTSVC_IO_ERROR;
		goto Error_close_exit;
	}

	fd_set fd;
	struct timeval tv;
	while (1) {
		errno = 0;

		FD_ZERO(&fd);
		FD_SET(server_sockfd, &fd);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		memset(&recv_data, 0x00, sizeof(VcoreRequestData));
		memset(&send_data, 0x00, sizeof(VcoreResponseData));

		int ret = select(server_sockfd + 1, &fd, NULL, NULL, &tv);
		if (ret == 0) { // timeout
			SLOGD("cert-server timeout. exit.");
			break;
		}

		if (ret == -1) {
			SLOGE("select() error.");
			break;
		}

		if ((client_sockfd = accept(server_sockfd, (struct sockaddr*)&clientaddr, (socklen_t*)&client_len)) < 0) {
			SLOGE("Error in function accept().[socket desc :%d, error no :%d].", client_sockfd, errno);
			continue;
		}

		SLOGD("cert-server Accept! client sock[%d]", client_sockfd);

		if (setsockopt (client_sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
			SLOGE("Error in Set SO_RCVTIMEO Socket Option");
			send_data.result = CERTSVC_FAIL;
			goto Error_close_exit;
		}

		if (setsockopt (client_sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
			SLOGE("Error in Set SO_SNDTIMEO Socket Option");
			send_data.result = CERTSVC_FAIL;
			goto Error_close_exit;
		}

		SLOGD("Connected to a client...");

		read_len = recv(client_sockfd, (char*)&recv_data, sizeof(recv_data), 0);
		if (read_len < 0) {
			SLOGE("Error in function recv().");
			send_data.result = CERTSVC_FAIL;
			goto Error_close_exit;
		}

		SLOGD("revc request: reqType=%d", recv_data.reqType);

		switch (recv_data.reqType) {
		case CERTSVC_EXTRACT_CERT:
		{
			send_data.result = getCertificateDetailFromStore(
					cert_store_db,
					recv_data.storeType,
					recv_data.certType,
					recv_data.gname,
					send_data.dataBlock,
					&send_data.dataBlockLen);
			result = send(client_sockfd, (char*)&send_data, sizeof(send_data), 0);
			break;
		}

		case CERTSVC_EXTRACT_SYSTEM_CERT:
		{
			send_data.result = getCertificateDetailFromSystemStore(
					cert_store_db,
					recv_data.gname,
					send_data.dataBlock,
					&send_data.dataBlockLen);
			result = send(client_sockfd, (char*)&send_data, sizeof(send_data), 0);
			break;
		}

		case CERTSVC_DELETE_CERT:
		{
			send_data.result = deleteCertificateFromStore(
					cert_store_db,
					recv_data.storeType,
					recv_data.gname);
			if (send_data.result == CERTSVC_SUCCESS)
				send_data.result = update_ca_certificate_file(cert_store_db, NULL, 0);
			result = send(client_sockfd, (char*)&send_data, sizeof(send_data), 0);
			break;
		}

		case CERTSVC_GET_CERTIFICATE_STATUS:
		{
			send_data.result = getCertificateStatusFromStore(
					cert_store_db,
					recv_data.storeType,
					recv_data.gname,
					&send_data.certStatus);
			result = send(client_sockfd, (char*)&send_data, sizeof(send_data), 0);
			break;
		}

		case CERTSVC_SET_CERTIFICATE_STATUS:
		{
			send_data.result = setCertificateStatusToStore(
					cert_store_db,
					recv_data.storeType,
					recv_data.is_root_app,
					recv_data.gname,
					recv_data.certStatus);
			if (send_data.result == CERTSVC_SUCCESS)
				send_data.result = update_ca_certificate_file(cert_store_db, NULL, 0);
			result = send(client_sockfd, (char*)&send_data, sizeof(send_data), 0);
			break;
		}

		case CERTSVC_CHECK_ALIAS_EXISTS:
		{
			send_data.result = checkAliasExistsInStore(
					cert_store_db,
					recv_data.storeType,
					recv_data.gname,
					&send_data.certStatus);
			result = send(client_sockfd, (char*)&send_data, sizeof(send_data), 0);
			break;
		}

		case CERTSVC_INSTALL_CERTIFICATE:
		{
			send_data.result = installCertificateToStore(
					cert_store_db,
					recv_data.storeType,
					recv_data.gname,
					recv_data.common_name,
					recv_data.private_key_gname,
					recv_data.associated_gname,
					recv_data.dataBlock,
					recv_data.dataBlockLen,
					recv_data.certType);

			if ((send_data.result == CERTSVC_SUCCESS) && ((recv_data.certType == PEM_CRT) || (recv_data.certType == P12_TRUSTED)))
				send_data.result = update_ca_certificate_file(cert_store_db, recv_data.dataBlock, recv_data.dataBlockLen);
			result = send(client_sockfd, (char*)&send_data, sizeof(send_data), 0);
			break;
		}

		case CERTSVC_GET_CERTIFICATE_LIST:
		case CERTSVC_GET_USER_CERTIFICATE_LIST:
		case CERTSVC_GET_ROOT_CERTIFICATE_LIST:
		{
			send_data.result = getCertificateListFromStore(
					cert_store_db,
					recv_data.reqType,
					recv_data.storeType,
					recv_data.is_root_app,
					&certListBuffer,
					&bufferLen,
					&send_data.certCount);
			result = send(client_sockfd, (char*)&send_data, sizeof(send_data), 0);
			if (bufferLen > 0)
				result = send(client_sockfd, certListBuffer, bufferLen, 0);

			break;
		}

		case CERTSVC_GET_CERTIFICATE_ALIAS:
		{
			send_data.result = getCertificateAliasFromStore(
					cert_store_db,
					recv_data.storeType,
					recv_data.gname,
					send_data.common_name);
			result = send(client_sockfd, (char*)&send_data, sizeof(send_data), 0);
			break;
		}

		case CERTSVC_LOAD_CERTIFICATES:
		{
			send_data.result = loadCertificatesFromStore(
					cert_store_db,
					recv_data.storeType,
					recv_data.gname,
					&certBlockBuffer,
					&blockBufferLen,
					&send_data.certBlockCount);
			result = send(client_sockfd, (char*)&send_data, sizeof(send_data), 0);
			if (blockBufferLen > 0)
				result = send(client_sockfd, certBlockBuffer, blockBufferLen, 0);
			break;
		}

		default:
			SLOGE("Input error. Please check request type");
			break;
		}

		if (result <= 0) {
			SLOGE("send failed :%d, errno %d try once", result, errno);
			//result = send(client_sockfd, (char*)&send_data, sizeof(send_data), 0);
			//SLOGE("retry result :%d, errno %d", result, errno);
		}

		close(client_sockfd);
	}

Error_close_exit:
	close(server_sockfd);
	if (cert_store_db) {
		sqlite3_close(cert_store_db);
		cert_store_db = NULL;
	}

	if (certListBuffer)
		free(certListBuffer);

	if (certBlockBuffer)
		free(certBlockBuffer);

	if (client_sockfd >= 0) {
		result = send(client_sockfd, (char*)&send_data, sizeof(send_data), 0);
		close(client_sockfd);
	}
	else
		SLOGE("cannot connect to client socket.");

	SLOGI("CertSvcServerComm done.");
}

int main(void)
{
	SLOGI("cert-server start");
	CertSvcServerComm();
	SLOGI("cert-server end");

	return 0;
}
