/*
 * certification service
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd All Rights Reserved 
 *
 * Contact: Kidong Kim <kd0228.kim@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include <openssl/x509.h>

#include "cert-service.h"
#include "cert-service-util.h"
#include "cert-service-debug.h"
#include "cert-service-store.h"

int get_file_full_path(char* originalName, const char* location, char* outBuf)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	char pathLocation[CERT_SVC_MAX_FILE_NAME_SIZE];
	char buf[CERT_SVC_MAX_FILE_NAME_SIZE];
	char* token = NULL;
	char seps[] = "_";
	int nameSize = 0 ;

	if (originalName  == NULL) {
		SLOGE("[ERR][%s] Check your parameter. Maybe file path is NULL.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	nameSize = strlen(originalName);

	if (nameSize <= 0 || nameSize >= CERT_SVC_MAX_FILE_NAME_SIZE) {
		SLOGE("[ERR][%s] Check your parameter. File path is too long.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	memset(buf, 0x00, sizeof(buf));
	memset(pathLocation, 0x00, sizeof(pathLocation));

	if(location == NULL) { 	// use default path
		strncpy(buf, CERT_SVC_STORE_PATH_DEFAULT, sizeof(buf) - 1);
	}
	else {
		int locSize = strlen(location) + strlen(CERT_SVC_STORE_PATH);

		if (locSize <= 0 || locSize >= CERT_SVC_MAX_FILE_NAME_SIZE) {
			SLOGE("[ERR][%s] Check your parameter. Location is too long.\n", __func__);
			ret = CERT_SVC_ERR_INVALID_PARAMETER;
			goto err;
		}

		strncpy(pathLocation, location, sizeof(pathLocation) - 1);

		strncpy(buf, CERT_SVC_STORE_PATH, sizeof(buf) - 1);

		token = strtok(pathLocation, seps);

		while(token) {
			if((strlen(buf) + strlen(token)) < (CERT_SVC_MAX_FILE_NAME_SIZE - 1)) {
					strncat(buf, token, strlen(token));
					strncat(buf, "/", 1);
					token = strtok(NULL, seps);
			}
			else {
				ret = CERT_SVC_ERR_INVALID_PARAMETER;
				goto err;
			}
		}
	}

	if ((nameSize + strlen(buf)) >= CERT_SVC_MAX_FILE_NAME_SIZE) {
		SLOGE("[ERR][%s] Check your parameter. File path is too long.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	strncat(buf, originalName, nameSize);
	strncpy(outBuf, buf, CERT_SVC_MAX_FILE_NAME_SIZE - 1);
	outBuf[ CERT_SVC_MAX_FILE_NAME_SIZE - 1] = '\0';

err:
	return ret;
}

int _add_certificate_to_store(const char* filePath, const char* location)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	/* get real file name */
	char* realFileName = NULL;
	char* fileFullPath = NULL;
	/* open file and copy */
	FILE* fp_in = NULL;
	FILE* fp_out = NULL;
	unsigned long int inFileLen = 0;
	char* fileContent = NULL;

	/* initialize variable */
	fileFullPath = (char*)malloc(sizeof(char) * CERT_SVC_MAX_FILE_NAME_SIZE);
	if(fileFullPath == NULL) {
		SLOGE("[ERR][%s] Fail to allocate memory.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(fileFullPath, 0x00, CERT_SVC_MAX_FILE_NAME_SIZE);

	/* get real file name */
	realFileName = strrchr(filePath, '/');
	if(realFileName == NULL) {
		SLOGE("[ERR][%s] File path MUST be absolute path\n", __func__);
		ret = CERT_SVC_ERR_FILE_IO;
		goto err;
	}
	
	/* get real file full path */
	get_file_full_path((realFileName + 1), location, fileFullPath);

	/* file open and write */
	if(!(fp_in = fopen(filePath, "rb"))) {
		SECURE_SLOGE("[ERR][%s] Fail to open file, [%s]\n", __func__, filePath);
		ret = CERT_SVC_ERR_FILE_IO;
		goto err;
	}
	if(!(fp_out = fopen(fileFullPath, "wb"))) {
		SECURE_SLOGE("[ERR][%s] Fail to open file, [%s]\n", __func__, fileFullPath);
		if(errno == EACCES)
			ret = CERT_SVC_ERR_PERMISSION_DENIED;
		else
			ret = CERT_SVC_ERR_FILE_IO;
		goto err;
	}

	if((ret = cert_svc_util_get_file_size(filePath, &inFileLen)) != CERT_SVC_ERR_NO_ERROR) {
		SECURE_SLOGE("[ERR][%s] Fail to get file size, [%s]\n", __func__, filePath);
		goto err;
	}

	fileContent = (char*)malloc(sizeof(char) * (int)inFileLen);
	if(fileContent == NULL) {
		SLOGE("[ERR][%s] Fail to allocate memory\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(fileContent, 0x00, inFileLen);

	if(fread(fileContent, sizeof(char), inFileLen, fp_in) != inFileLen) {
		SECURE_SLOGE("[ERR][%s] Fail to read file, [%s]\n", __func__, filePath);
		ret = CERT_SVC_ERR_FILE_IO;
		goto err;
	}
	if(fwrite(fileContent, sizeof(char), inFileLen, fp_out) != inFileLen) {
		SECURE_SLOGE("[ERR][%s] Fail to write file, [%s]\n", __func__, fileFullPath);
		ret = CERT_SVC_ERR_FILE_IO;
		goto err;
	}

err:
	if(fp_in != NULL)
		fclose(fp_in);
	if(fp_out != NULL)
		fclose(fp_out);

	if(fileContent != NULL)
		free(fileContent);
	if(fileFullPath != NULL)
		free(fileFullPath);

	return ret;
}

int _delete_certificate_from_store(const char* fileName, const char* location)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	char* fileFullPath = NULL;

	/* initialize variable */
	fileFullPath = (char*)malloc(sizeof(char) * CERT_SVC_MAX_FILE_NAME_SIZE);
	if(fileFullPath == NULL) {
		SLOGE("[ERR][%s] Fail to allocate memory.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(fileFullPath, 0x00, CERT_SVC_MAX_FILE_NAME_SIZE);

	/* get file full path */
	get_file_full_path((char*)fileName, location, fileFullPath);

	/* delete designated certificate */
	if(unlink(fileFullPath) == -1) {
		SECURE_SLOGE("[ERR][%s] Fail to delete file, [%s]\n", __func__, fileName);
		if(errno == EACCES)
			ret = CERT_SVC_ERR_PERMISSION_DENIED;
		else
			ret = CERT_SVC_ERR_FILE_IO;
	}

err:
	if(fileFullPath != NULL)
		free(fileFullPath);
	
	return ret;
}
