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

#include "cert-service.h"
#include "cert-service-util.h"
#include "cert-service-debug.h"
#include "cert-service-store.h"
#include "cert-service-process.h"

/* Set visibility */
#ifndef CERT_SVC_API
#define CERT_SVC_API	__attribute__((visibility("default")))
#endif

#define CRT_FILE_PATH	"/opt/usr/share/certs/ca-certificate.crt"

CERT_SVC_API
int cert_svc_add_certificate_to_store(const char* filePath, const char* location)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	char _filePath[CERT_SVC_MAX_FILE_NAME_SIZE];

	memset(_filePath, 0x00, CERT_SVC_MAX_FILE_NAME_SIZE);

	if(filePath == NULL) {
		SLOGE("[ERR][%s] Check your parameter. Maybe file path is NULL.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	if(filePath[0] != '/') {	// not absolute path, this is regarded relative file path
		getcwd(_filePath, CERT_SVC_MAX_FILE_NAME_SIZE);
		strncat(_filePath, "/", 1);
		strncat(_filePath, filePath, strlen(filePath));
	}
	else
		strncpy(_filePath, filePath, strlen(filePath));

	ret = _add_certificate_to_store(_filePath, location);

	if(ret != CERT_SVC_ERR_NO_ERROR) {
		SECURE_SLOGE("[ERR][%s] Fail to store certificate, [%s]\n", __func__, _filePath);
		goto err;
	}
	SECURE_SLOGD("[%s] Success to add certificate [%s].\n", __func__, filePath);

err:
	return ret;
}

CERT_SVC_API
int cert_svc_delete_certificate_from_store(const char* fileName, const char* location)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	if((fileName == NULL) || (fileName[0] == '/')) {
		SLOGE("[ERR][%s] Check your parameter. Maybe file name is NULL or is not single name.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	ret = _delete_certificate_from_store(fileName, location);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		SECURE_SLOGE("[ERR][%s] Fail to delete certificate, [%s]\n", __func__, fileName);
		goto err;
	}
	SECURE_SLOGD("[%s] Success to delete certificate [%s].\n", __func__, fileName);

err:
	return ret;
}

CERT_SVC_API
int cert_svc_verify_certificate(CERT_CONTEXT* ctx, int* validity)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	if((ctx == NULL) || (ctx->certBuf == NULL)) {
		SLOGE("[ERR][%s] Check your parameter. Cannot find certificate.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}
	if(ctx->fileNames != NULL) {
		SLOGE("[ERR][%s] Check your parameter. fileNames field is NOT NULL.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	/* memory allocation for root file path */
	if(!(ctx->fileNames = (cert_svc_filename_list*)malloc(sizeof(cert_svc_filename_list)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	if(!(ctx->fileNames->filename = (char*)malloc(sizeof(char) * CERT_SVC_MAX_FILE_NAME_SIZE))) {
		SLOGE("[ERR][%s] Fail to allocate memory.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(ctx->fileNames->filename, 0x00, CERT_SVC_MAX_FILE_NAME_SIZE);
	ctx->fileNames->next = NULL;

	/* call verify function */
	if((ret = _verify_certificate(ctx->certBuf, &(ctx->certLink), ctx->fileNames, validity)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to verify certificate.\n", __func__);
		goto err;
	}

	SLOGD("[%s] Success to verify certificate.\n", __func__);

err:
	return ret;
}

/*
 * message : unsigned character string
 * signature : base64 encoded string
 */
CERT_SVC_API
int cert_svc_verify_signature(CERT_CONTEXT* ctx, unsigned char* message, int msgLen, unsigned char* signature, char* algo, int* validity)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	if((message == NULL) || (signature == NULL) || (ctx == NULL) || (ctx->certBuf == NULL)) {
		SLOGE("[ERR][%s] Invalid parameter, please check your parameter\n", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	if((ret = _verify_signature(ctx->certBuf, message, msgLen, signature, algo, validity)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to verify signature.\n", __func__);
		goto err;
	}
	SLOGD("[%s] Success to verify signature.\n", __func__);

err:
	return ret;
}

CERT_SVC_API
int cert_svc_extract_certificate_data(CERT_CONTEXT* ctx)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	/* chec parameter */
	if(ctx == NULL) {
		SLOGE("[ERR][%s] Check your parameter.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	/* check context */
	if(ctx->certBuf == NULL) {
		SLOGE("[ERR][%s] Cannot find certificate to be extracted.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}
	if(ctx->certDesc != NULL) {
		SLOGE("[ERR][%s] certDesc is not NULL. cannot load content.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	/* memory allocation of cert descriptor */
	if(!(ctx->certDesc = (cert_svc_cert_descriptor*)malloc(sizeof(cert_svc_cert_descriptor)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(ctx->certDesc, 0x00, sizeof(cert_svc_cert_descriptor));

	/* call extract function */
	if((ret = _extract_certificate_data(ctx->certBuf, ctx->certDesc)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to extract certificate data.\n", __func__);
		goto err;
	}
	SLOGD("[%s] Success to extract certificate.\n", __func__);

err:
	return ret;
}

CERT_SVC_API
int cert_svc_search_certificate(CERT_CONTEXT* ctx, search_field fldName, char* fldData)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	/* check parameter */
	if((ctx == NULL) || (fldName < SEARCH_FIELD_START ) || (fldName > SEARCH_FIELD_END) || (fldData == NULL)) {
		SLOGE("[ERR][%s] Invalid parameter. Check your parameter\n", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	/* check conext */
	if(ctx->fileNames != NULL) {
		SLOGE("[ERR][%s] fileNames field already be used.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}

	/* search specific field */
	if((ret = _search_certificate(&(ctx->fileNames), fldName, fldData)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to search sertificate.\n", __func__);
		goto err;
	}
	SLOGD("[%s] Success to search certificate(s).\n", __func__);

err:
	return ret;
}

CERT_SVC_API
CERT_CONTEXT* cert_svc_cert_context_init()
{
	CERT_CONTEXT* ctx = NULL;

	if(!(ctx = (CERT_CONTEXT*)malloc(sizeof(CERT_CONTEXT)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.\n", __func__);
		return NULL;
	}

	ctx->certBuf = NULL;
	ctx->certDesc = NULL;
	ctx->certLink = NULL;
	ctx->fileNames = NULL;

	SLOGD("[%s] Success to initialize context.\n", __func__);

	return ctx;
}

CERT_SVC_API
int cert_svc_cert_context_final(CERT_CONTEXT* context)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	if(context == NULL)	// already be freed
		goto err;

	// free certBuf
	if(context->certBuf != NULL) {
		if(context->certBuf->data != NULL)
			free(context->certBuf->data);
		context->certBuf->data = NULL;
		free(context->certBuf);
	}
	context->certBuf = NULL;

	release_certificate_data(context->certDesc);
	release_cert_list(context->certLink);
	release_filename_list(context->fileNames);

	// free context
	free(context);
	context = NULL;

	SLOGD("[%s] Success to finalize context.\n", __func__);

err:
	return ret;
}

CERT_SVC_API
int cert_svc_load_buf_to_context(CERT_CONTEXT* ctx, unsigned char* buf)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	int size = 0, decodedSize = 0;
	char* decodedStr = NULL;

	/* check parameter */
	if((ctx == NULL) || (buf == NULL)) {
		SLOGE("[ERR][%s] context or buf is NULL.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	/* memory allocation for ctx->certBuf */
	if(ctx->certBuf != NULL) {
		SLOGE("[ERR][%s] certBuf is already used. we cannot load buffer content.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}
	if(!(ctx->certBuf = (cert_svc_mem_buff*)malloc(sizeof(cert_svc_mem_buff)))) {
		SLOGE("[ERR][%s] Fail to allovate memory.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(ctx->certBuf, 0x00, sizeof(cert_svc_mem_buff));

	/* memory allocation for decoded string */
	size = strlen(buf);
	decodedSize = ((size / 4) * 3) + 1;

	if(!(decodedStr = (char*)malloc(sizeof(char) * decodedSize))) {
		SLOGE("[ERR][%s] Fail to allocate memory.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}

	/* decode */
	if((ret = cert_svc_util_base64_decode(buf, size, decodedStr, &decodedSize)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to decode string, ret: [%d]\n", __func__, ret);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		free(decodedStr);
		goto err;
	}

	/* load content to CERT_CONTEXT */
	ctx->certBuf->data = decodedStr;
	ctx->certBuf->size = decodedSize;

	SLOGD("[%s] Success to load certificate buffer content to context.\n", __func__);

err:
	return ret;
}

CERT_SVC_API
int cert_svc_load_file_to_context(CERT_CONTEXT* ctx, const char* filePath)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	/* check parameter */
	if((ctx == NULL) || (filePath == NULL)) {
		SLOGE("[ERR][%s] context or file path is NULL.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	/* memory allocation for (*ctx)->certBuf */
	if(ctx->certBuf != NULL) {
		SLOGE("[ERR][%s] certBuf is already used. we cannot load file.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}
	if(!(ctx->certBuf = (cert_svc_mem_buff*)malloc(sizeof(cert_svc_mem_buff)))) {
		SLOGE("[ERR][%s] Fail to allovate memory.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(ctx->certBuf, 0x00, sizeof(cert_svc_mem_buff));

	/* get content to (*ctx)->certBuf */
	if((ret = cert_svc_util_load_file_to_buffer(filePath, ctx->certBuf)) != CERT_SVC_ERR_NO_ERROR) {
		SECURE_SLOGE("[ERR][%s] Fail to load file, filepath: [%s], ret: [%d]\n", __func__, filePath, ret);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}
	
	SLOGD("[%s] Success to load certificate file content to context.\n", __func__);

err:
	return ret;
}

CERT_SVC_API
int cert_svc_push_buf_into_context(CERT_CONTEXT *ctx, unsigned char* buf)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_linked_list* cur = NULL;
	cert_svc_linked_list* new = NULL;
	int size = 0, decodedSize = 0;
	char* decodedStr = NULL;

	/* check parameter */
	if((ctx == NULL) || (buf == NULL)) {
		SLOGE("[ERR][%s] context or buf is NULL.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	/* memory alloction new item */
	if(!(new = (cert_svc_linked_list*)malloc(sizeof(cert_svc_linked_list)))) {
		SLOGE("[ERR][%s] Fail to allcate memory.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	if(!(new->certificate = (cert_svc_mem_buff*)malloc(sizeof(cert_svc_mem_buff)))) {
		SLOGE("[ERR][%s] Fail to allcate memory.\n", __func__);
		free(new);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}

	/* memory allocation for decoded string */
	size = strlen(buf);
	decodedSize = ((size / 4) * 3) + 1;

	if(!(decodedStr = (char*)malloc(sizeof(char) * decodedSize))) {
		SLOGE("[ERR][%s] Fail to allocate memory.\n", __func__);
		release_cert_list(new);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}

	/* decode */
	if((ret = cert_svc_util_base64_decode(buf, size, decodedStr, &decodedSize)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to decode string, ret: [%d]\n", __func__, ret);
		release_cert_list(new);
		free(decodedStr);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}

	/* load content to CERT_CONTEXT */
	new->certificate->data = decodedStr;
	new->certificate->size = decodedSize;
	new->next = NULL;

	/* attach new structure */
	if(ctx->certLink == NULL)
		ctx->certLink = new;
	else {
		cur = ctx->certLink;
		while(cur->next)
			cur = cur->next;
		cur->next = new;
	}
	
	SLOGD("[%s] Success to push certificate buffer content to context.\n", __func__);

err:
	return ret;
}

CERT_SVC_API
int cert_svc_push_file_into_context(CERT_CONTEXT *ctx, const char* filePath)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_linked_list* cur = NULL;
	cert_svc_linked_list* new = NULL;

	/* check parameter */
	if((ctx == NULL) || (filePath == NULL)) {
		SLOGE("[ERR][%s] context or file path is NULL.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	/* memory alloction new item */
	if(!(new = (cert_svc_linked_list*)malloc(sizeof(cert_svc_linked_list)))) {
		SLOGE("[ERR][%s] Fail to allcate memory.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(new, 0x00, sizeof(cert_svc_linked_list));
	if(!(new->certificate = (cert_svc_mem_buff*)malloc(sizeof(cert_svc_mem_buff)))) {
		SLOGE("[ERR][%s] Fail to allcate memory.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		free(new);
		goto err;
	}
	memset(new->certificate, 0x00, sizeof(cert_svc_mem_buff));

	/* get content to ctx->certBuf */
	if((ret = cert_svc_util_load_file_to_buffer(filePath, new->certificate)) != CERT_SVC_ERR_NO_ERROR) {
		SECURE_SLOGE("[ERR][%s] Fail to load file, filepath: [%s], ret: [%d]\n", __func__, filePath, ret);
		release_cert_list(new);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}
	new->next = NULL;

	/* attach new structure */
	if(ctx->certLink == NULL) 	// first
		ctx->certLink = new;
	else {
		cur = ctx->certLink;
		while(cur->next != NULL)
			cur = cur->next;

		cur->next = new;
	}
	
	SLOGD("[%s] Success to push certificate file content to context.\n", __func__);

err:
	return ret;
}

CERT_SVC_API
int cert_svc_load_PFX_file_to_context(CERT_CONTEXT* ctx, unsigned char** privateKey, int* priKeyLen, const char* filePath, char* passPhrase)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	/* check parameter */
	if((ctx == NULL) || (filePath == NULL)) {
		SLOGE("[ERR][%s] context or file path is NULL.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	/* memory allocation for ctx->certBuf */
	if(ctx->certBuf != NULL) {
		SLOGE("[ERR][%s] certBuf is already used. we cannot load file.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}
	if(!(ctx->certBuf = (cert_svc_mem_buff*)malloc(sizeof(cert_svc_mem_buff)))) {
		SLOGE("[ERR][%s] Fail to allovate memory.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(ctx->certBuf, 0x00, sizeof(cert_svc_mem_buff));

	/* get content to ctx->certBuf */
	if((ret = cert_svc_util_load_PFX_file_to_buffer(filePath, ctx->certBuf, ctx->certLink, privateKey, priKeyLen, passPhrase)) != CERT_SVC_ERR_NO_ERROR) {
		SECURE_SLOGE("[ERR][%s] Fail to load file, filepath: [%s], ret: [%d]\n", __func__, filePath, ret);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}
	
	SLOGD("[%s] Success to load certificate file content to context.\n", __func__);

err:
	return ret;
}

CERT_SVC_API
int cert_svc_check_ocsp_status(CERT_CONTEXT* ctx, const char* uri)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	/* check parameter */
	if((ctx == NULL) || (ctx->certBuf == NULL)) {
		SLOGE("[ERR][%s] certBuf must have value.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}

	/* check revocation status */
	if((ret = _check_ocsp_status(ctx->certBuf, uri)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to check revocation status.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_CERTIFICATE;
		goto err;
	}

err:
	return ret;
}

CERT_SVC_API
char* cert_svc_get_certificate_crt_file_path(void)
{
	return CRT_FILE_PATH;
}

