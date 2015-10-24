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
 * @file     cert-svc-client.c
 * @author   Madhan A K (madhan.ak@samsung.com)
 *           Kyungwook Tak (k.tak@samsung.com)
 * @version  1.0
 * @brief    cert-svc client interface for cert-server.
 */

#include <sys/stat.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <dlog.h>

#include <cert-svc-client.h>

void initialize_res_data(VcoreResponseData *pData)
{
	memset(pData->dataBlock, 0, VCORE_MAX_RECV_DATA_SIZE);
	memset(pData->common_name, 0, VCORE_MAX_FILENAME_SIZE * 2 + 1);
	pData->dataBlockLen = 0;
	pData->certStatus = 0;
	pData->result = 0;
	pData->certList = NULL;
	pData->certCount = 0;
	pData->certBlockList = NULL;
	pData->certBlockCount = 0;
}

void initialize_req_data(VcoreRequestData *pData)
{
	memset(pData->gname, 0, VCORE_MAX_FILENAME_SIZE+1);
	memset(pData->common_name, 0, VCORE_MAX_FILENAME_SIZE+1);
	memset(pData->private_key_gname, 0, VCORE_MAX_FILENAME_SIZE+1);
	memset(pData->associated_gname, 0, VCORE_MAX_FILENAME_SIZE+1);
	memset(pData->dataBlock, 0, VCORE_MAX_SEND_DATA_SIZE);
	pData->certStatus = 0;
	pData->storeType = -1;
	pData->reqType = -1;
	pData->dataBlockLen = -1;
	pData->is_root_app = -1;
}

int _recv_fixed_lenghth(int sockfd, char *buff, int length)
{
	int offset = 0;
	int remaining = length;
	int read_len = 0;
	while(remaining > 0) {
		read_len = recv(sockfd, buff + offset, remaining, 0);
		if(read_len <= 0)
			return offset;
		remaining -= read_len;
		offset += read_len;
	}
	return offset;
}

VcoreRequestData* set_request_data(
	int reqType,
	CertStoreType storeType,
	int is_root_app,
	const char *pGroupName,
	const char *common_name,
	const char *private_key_gname,
	const char *associated_gname,
	const char *pData,
	size_t dataLen,
	CertType certType,
	int certStatus)
{
	VcoreRequestData* pReqData = (VcoreRequestData*)malloc(sizeof(VcoreRequestData));
	if (!pReqData) {
		LOGE("Failed to malloc VcoreRequestData");
		return NULL;
	}
	initialize_req_data(pReqData);

	pReqData->reqType = reqType;
	pReqData->storeType = (CertStoreType) storeType;
	pReqData->dataBlockLen = dataLen;
	pReqData->certType = certType;
	pReqData->certStatus = certStatus;
	pReqData->is_root_app = is_root_app;

	if (pGroupName) {
		if (strlen(pGroupName) > VCORE_MAX_FILENAME_SIZE) {
			LOGE("The data name is too long");
			free(pReqData);
			return NULL;
		}
		strncpy(pReqData->gname, pGroupName, VCORE_MAX_FILENAME_SIZE);
		pReqData->gname[strlen(pGroupName)] = '\0';
	}

	if (common_name) {
		if (strlen(common_name) > VCORE_MAX_FILENAME_SIZE) {
			LOGE("The length of the path specified is too long");
			free(pReqData);
			return NULL;
		}
		strncpy(pReqData->common_name, common_name, VCORE_MAX_FILENAME_SIZE);
		pReqData->common_name[strlen(common_name)] = '\0';
	}

	if (private_key_gname) {
		if (strlen(private_key_gname) > VCORE_MAX_FILENAME_SIZE) {
			LOGE("The private key gname is too long");
			free(pReqData);
			return NULL;
		}
		strncpy(pReqData->private_key_gname, private_key_gname, VCORE_MAX_FILENAME_SIZE);
		pReqData->private_key_gname[strlen(private_key_gname)] = '\0';
	}

	if (associated_gname) {
		if (strlen(associated_gname) > VCORE_MAX_FILENAME_SIZE) {
			LOGE("The associated gname is too long");
			free(pReqData);
			return NULL;
		}
		strncpy(pReqData->associated_gname, associated_gname, VCORE_MAX_FILENAME_SIZE);
		pReqData->associated_gname[strlen(associated_gname)] = '\0';
	}

	if (dataLen != 0 && pData != NULL) {
		if (dataLen > VCORE_MAX_SEND_DATA_SIZE) {
			LOGE("The data length is too long [%d]", dataLen);
			free(pReqData);
			return NULL;
		}
		memcpy(pReqData->dataBlock, pData, dataLen);
	}
	return pReqData;
}


VcoreResponseData cert_svc_client_comm(VcoreRequestData* pClientData) {

	int sockfd = 0;
	int clientLen = 0;
	int tempSockLen = 0;
	int read_len = 0;
	int i = 0;
	struct sockaddr_un clientaddr;
	VcoreResponseData recvData;
	initialize_res_data(&recvData);

	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		LOGE("Error in function socket()..");
		recvData.result = VCORE_SOCKET_ERROR;
		goto Error_exit;
	}

	tempSockLen = strlen(VCORE_SOCK_PATH);
	bzero(&clientaddr, sizeof(clientaddr));
	clientaddr.sun_family = AF_UNIX;
	strncpy(clientaddr.sun_path, VCORE_SOCK_PATH, tempSockLen);
	clientaddr.sun_path[tempSockLen] = '\0';
	clientLen = sizeof(clientaddr);

	struct timeval timeout;
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;

	if (setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
		LOGE("Error in Set SO_RCVTIMEO Socket Option");
		recvData.result = VCORE_SOCKET_ERROR;
		goto Error_close_exit;
	}

	if (setsockopt (sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
		LOGE("Error in Set SO_SNDTIMEO Socket Option");
		recvData.result = VCORE_SOCKET_ERROR;
		goto Error_close_exit;
	}

	if (connect(sockfd, (struct sockaddr*)&clientaddr, clientLen) < 0) {
		LOGE("Error in function connect()..");
		recvData.result = VCORE_SOCKET_ERROR;
		goto Error_close_exit;
	}

	if (write(sockfd, (char*)pClientData, sizeof(VcoreRequestData)) < 0) {
		LOGE("Error in function write()..");
		recvData.result = VCORE_SOCKET_ERROR;
		goto Error_close_exit;
	}

	read_len = _recv_fixed_lenghth(sockfd, (char*)&recvData, sizeof(recvData));
	if (read_len < 0) {
		LOGE("Error in function read()..");
		recvData.result = VCORE_SOCKET_ERROR;
		goto Error_close_exit;
	}

	if(recvData.certCount > 0) {
		recvData.certList = (VcoreCertResponseData *) malloc(recvData.certCount * sizeof(VcoreCertResponseData));
		if (!recvData.certList) {
			LOGE("Failed to allocate memory");
			recvData.result = VCORE_SOCKET_ERROR;
			goto Error_close_exit;
		}
		memset(recvData.certList, 0x00, recvData.certCount * sizeof(VcoreCertResponseData));
		for(i=0; i<recvData.certCount; i++) {
			read_len = _recv_fixed_lenghth(sockfd, (char*)(recvData.certList + i), sizeof(VcoreCertResponseData));
			if (read_len < 0) {
				LOGE("Error in function read()..");
				recvData.result = VCORE_SOCKET_ERROR;
				goto Error_close_exit;
			}
		}
	}

	if(recvData.certBlockCount > 0) {
		recvData.certBlockList = (ResponseCertBlock *) malloc(recvData.certBlockCount * sizeof(ResponseCertBlock));
		if (!recvData.certBlockList) {
			LOGE("Failed to allocate memory");
			recvData.result = VCORE_SOCKET_ERROR;
			goto Error_close_exit;
		}
		memset(recvData.certBlockList, 0x00, recvData.certBlockCount * sizeof(ResponseCertBlock));
		for(i=0; i<recvData.certBlockCount; i++) {
			read_len = _recv_fixed_lenghth(sockfd, (char*)(recvData.certBlockList + i), sizeof(ResponseCertBlock));
			if (read_len < 0) {
				LOGE("Error in function read()..");
				recvData.result = VCORE_SOCKET_ERROR;
				goto Error_close_exit;
			}
		}
	}

Error_close_exit:
	close(sockfd);
	if (recvData.result == VCORE_SOCKET_ERROR) {
		free(recvData.certList);
		recvData.certList = NULL;
		recvData.certCount = 0;

		free(recvData.certBlockList);
		recvData.certBlockList = NULL;
		recvData.certBlockCount = 0;
	}

Error_exit:
	return recvData;
}

int vcore_client_install_certificate_to_store(
	CertStoreType storeType,
	const char *gname,
	const char *common_name,
	const char *private_key_gname,
	const char *associated_gname,
	const char *certData,
	size_t certSize,
	CertType certType)
{
	VcoreRequestData* pSendData = NULL;
	VcoreResponseData recvData;
	initialize_res_data(&recvData);

	if (!gname && !certData) {
		LOGE("Invalid input argument.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	pSendData = set_request_data(
			CERTSVC_INSTALL_CERTIFICATE,
			storeType,
			DISABLED,
			gname,
			common_name,
			private_key_gname,
			associated_gname,
			certData,
			certSize,
			certType, 0);
	if (pSendData == NULL) {
		LOGE("Failed to set request data");
		return CERTSVC_WRONG_ARGUMENT;
	}

	recvData = cert_svc_client_comm(pSendData);
	free(pSendData);
	return recvData.result;
}

int vcore_client_set_certificate_status_to_store(CertStoreType storeType, int is_root_app, const char* gname, CertStatus status) {

	VcoreRequestData* pSendData = NULL;
	VcoreResponseData recvData;
	initialize_res_data(&recvData);

	if (gname == NULL) {
		LOGE("Invalid input parameter.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	pSendData = set_request_data(CERTSVC_SET_CERTIFICATE_STATUS, storeType, is_root_app, gname, NULL, NULL, NULL, NULL, 0, 0, status);
	if (pSendData == NULL) {
		LOGE("Failed to set request data");
		return CERTSVC_WRONG_ARGUMENT;
	}

	recvData = cert_svc_client_comm(pSendData);
	free(pSendData);

	return recvData.result;
}

int vcore_client_get_certificate_status_from_store(CertStoreType storeType, const char* gname, int *status) {

	VcoreRequestData* pSendData = NULL;
	VcoreResponseData recvData;
	initialize_res_data(&recvData);

	if (gname == NULL) {
		LOGE("Invalid input parameter.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	pSendData = set_request_data(CERTSVC_GET_CERTIFICATE_STATUS, storeType, DISABLED, gname, NULL, NULL, NULL, NULL, 0, 0, 0);
	if (pSendData == NULL) {
		LOGE("Failed to set request data");
		return CERTSVC_WRONG_ARGUMENT;
	}

	recvData = cert_svc_client_comm(pSendData);
	free(pSendData);
	*status = recvData.certStatus;
	return recvData.result;
}

int vcore_client_check_alias_exist_in_store(CertStoreType storeType, const char* alias, int *status) {

	VcoreRequestData* pSendData = NULL;
	VcoreResponseData recvData;
	initialize_res_data(&recvData);

	if (alias == NULL) {
		LOGE("Invalid input parameter.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	pSendData = set_request_data(CERTSVC_CHECK_ALIAS_EXISTS, storeType, DISABLED,alias, NULL, NULL, NULL, NULL, 0, 0, 0);
	if (pSendData == NULL) {
		LOGE("Failed to set request data");
		return CERTSVC_WRONG_ARGUMENT;
	}

	recvData = cert_svc_client_comm(pSendData);
	free(pSendData);
	*status = recvData.certStatus;
	return recvData.result;
}

int vcore_client_get_certificate_from_store(CertStoreType storeType, const char* gname, char** certData, size_t* certSize, CertType certType) {

	char* outData = NULL;
	VcoreRequestData* pSendData = NULL;
	VcoreResponseData recvData;

	if (!gname || !certData || !certSize) {
		LOGE("Invalid input argument.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	initialize_res_data(&recvData);

	if (storeType == SYSTEM_STORE)  /* for extracting certificate from system store */
		pSendData = set_request_data(CERTSVC_EXTRACT_SYSTEM_CERT, storeType, DISABLED, gname, NULL, NULL, NULL, NULL, 0, certType, 0);
	else /* for extracting certificate from other stores */
		pSendData = set_request_data(CERTSVC_EXTRACT_CERT, storeType, DISABLED, gname, NULL, NULL, NULL, NULL, 0, certType, 0);

	if (pSendData == NULL) {
		LOGE("Failed to set request data.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	recvData = cert_svc_client_comm(pSendData);
	if (recvData.result < 0) {
		LOGE("An error occurred from server side err[%d]", recvData.result);
		free(pSendData);
		return recvData.result;
	}
	free(pSendData);

	if (recvData.dataBlockLen > 0 && recvData.dataBlockLen <= VCORE_MAX_RECV_DATA_SIZE) {
		outData = (char*)malloc(recvData.dataBlockLen + 1);
		memset(outData, 0x00, recvData.dataBlockLen +1);
		memcpy(outData, recvData.dataBlock, recvData.dataBlockLen);
		*certData = outData;
		*certSize = recvData.dataBlockLen;
	}
	else {
		LOGE("revcData length is wrong : %d", recvData.dataBlockLen);
		return CERTSVC_WRONG_ARGUMENT;
	}

	return recvData.result;
}

int vcore_client_delete_certificate_from_store(CertStoreType storeType, const char* gname) {

	VcoreRequestData* pSendData = NULL;
	VcoreResponseData recvData;
	initialize_res_data(&recvData);

	if (gname == NULL) {
		LOGE("Invalid input parameter.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	pSendData = set_request_data(CERTSVC_DELETE_CERT, storeType, DISABLED, gname, NULL, NULL, NULL, NULL, 0, 0, 0);
	if (pSendData == NULL) {
		LOGE("Failed to set request data");
		return CERTSVC_WRONG_ARGUMENT;
	}

	recvData = cert_svc_client_comm(pSendData);
	free(pSendData);
	return recvData.result;
}

int _vcore_client_get_certificate_list_from_store(int reqType, CertStoreType storeType, int is_root_app, 
									   CertSvcStoreCertList** certList, int* length)
{
	VcoreRequestData* pSendData = NULL;
	VcoreResponseData recvData;
	CertSvcStoreCertList* curr = NULL;
	CertSvcStoreCertList* prev = NULL;
	VcoreCertResponseData* cert = NULL;
	int tmplen = 0;
	int i=0;
	initialize_res_data(&recvData);


	pSendData = set_request_data(reqType, storeType, is_root_app, NULL, NULL, NULL, NULL, NULL, 0, 0, 0);
	if (pSendData == NULL) {
		LOGE("Failed to set request data");
		return CERTSVC_WRONG_ARGUMENT;
	}

	recvData = cert_svc_client_comm(pSendData);

	if(recvData.certCount > 0) {
		for(i=0; i<recvData.certCount; i++) {
		   cert = recvData.certList + i ;
		   curr = (CertSvcStoreCertList*) malloc(sizeof(CertSvcStoreCertList));
		   memset(curr, 0x00, sizeof(CertSvcStoreCertList));

		   tmplen = strlen(cert->gname);
		   curr->gname = (char*) malloc (sizeof(char) * (tmplen+ 1));
		   memset(curr->gname, 0x00, tmplen + 1);
		   memcpy(curr->gname, cert->gname, tmplen);

		   tmplen = strlen(cert->title);
		   curr->title = (char*) malloc (sizeof(char) * (tmplen+ 1));
		   memset(curr->title, 0x00, tmplen + 1);
		   memcpy(curr->title, cert->title, tmplen);

		   curr->status = cert->status;
		   curr->storeType = cert->storeType;

		   if(prev == NULL) {
			   *certList = curr;
		   }else {
			   prev->next = curr;
		   }
		   prev = curr;
		}
	}

	*length = recvData.certCount;

	LOGI("get_certificate_list_from_store: result=%d", recvData.result);
	if(recvData.certList != NULL)
		free(recvData.certList);
	free(pSendData);
	return recvData.result;
}

int vcore_client_get_certificate_list_from_store(CertStoreType storeType, int is_root_app, 
									   CertSvcStoreCertList** certList, int* length)
{
	return _vcore_client_get_certificate_list_from_store(CERTSVC_GET_CERTIFICATE_LIST, storeType, is_root_app,
									   certList, length);
}

int vcore_client_get_root_certificate_list_from_store(CertStoreType storeType,  
									   CertSvcStoreCertList** certList, int* length)
{
	return _vcore_client_get_certificate_list_from_store(CERTSVC_GET_ROOT_CERTIFICATE_LIST, storeType, 0,
									   certList, length);
}

int vcore_client_get_end_user_certificate_list_from_store(CertStoreType storeType,  
									   CertSvcStoreCertList** certList, int* length)
{
	return _vcore_client_get_certificate_list_from_store(CERTSVC_GET_USER_CERTIFICATE_LIST, storeType, 0,
									   certList, length);
}

int vcore_client_get_certificate_alias_from_store(CertStoreType storeType, const char *gname, char **alias)
{
	VcoreRequestData* pSendData = NULL;
	VcoreResponseData recvData;
	initialize_res_data(&recvData);

	if (gname == NULL) {
		LOGE("Invalid input parameter.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	pSendData = set_request_data(CERTSVC_GET_CERTIFICATE_ALIAS, storeType, DISABLED, gname, NULL, NULL, NULL, NULL, 0, 0, 0);
	if (pSendData == NULL) {
		LOGE("Failed to set request data");
		return CERTSVC_WRONG_ARGUMENT;
	}

	recvData = cert_svc_client_comm(pSendData);

	*alias = strndup(recvData.common_name, sizeof(recvData.common_name));
	free(pSendData);
	return recvData.result;
}

int vcore_client_load_certificates_from_store(CertStoreType storeType, const char *gname, char ***certs, int *ncerts)
{
	VcoreRequestData* pSendData = NULL;
	VcoreResponseData recvData;
	ResponseCertBlock* cert = NULL;
	int i=0;
	initialize_res_data(&recvData);

	pSendData = set_request_data(CERTSVC_LOAD_CERTIFICATES, storeType, DISABLED, gname, NULL, NULL, NULL, NULL, 0, 0, 0);
	if (pSendData == NULL) {
		LOGE("Failed to set request data");
		return CERTSVC_WRONG_ARGUMENT;
	}

	recvData = cert_svc_client_comm(pSendData);

	*ncerts = recvData.certBlockCount;
	*certs = (char**)malloc((recvData.certBlockCount+1) * sizeof(char *));
	(*certs)[recvData.certBlockCount] = NULL;
	LOGD("vcore_client_load_certificates_from_store. result=%d, ncerts=%d", recvData.result, *ncerts);
	if(recvData.certBlockCount > 0) {
		for(i=0; i<recvData.certBlockCount; i++) {
		   cert = recvData.certBlockList + i ;
		   (*certs)[i] = strndup(cert->dataBlock, cert->dataBlockLen);
		   LOGD("vcore_client_load_certificates_from_store. cert=%s", (*certs)[i]);
		}
	}

	if(recvData.certBlockList != NULL)
		free(recvData.certBlockList);
	free(pSendData);
	return recvData.result;

}
