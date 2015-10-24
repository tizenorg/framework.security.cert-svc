/*
 * certification service
 *
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <dlfcn.h>
#include <fcntl.h>

#include "cert-service.h"
#include "cert-service-util.h"
#include "cert-service-debug.h"
#include "cert-service-store.h"
#include "cert-service-process.h"

/* Set visibility */
#ifndef CERT_SVC_API
#define CERT_SVC_API	__attribute__((visibility("default")))
#endif

#define CRT_FILE_PATH	"/opt/share/ca-certificates/ca-certificate.crt"
#define AUTHOR_SIGNATURE "author-signature.xml"
#define DISTRIBUTOR_SIGNATURE "signature1.xml"

int __is_certified_device(const unsigned char* cert, int certSize)
{
	int (*CheckFunc)(const unsigned char *, int) = NULL;
	int (*CheckFile)(void) = NULL;
	void *handle = NULL;
	int result;
	unsigned char *base64cert = NULL;
	int base64certSize = 0;

	handle = dlopen("libcert-svc-vcore.so", RTLD_LAZY | RTLD_GLOBAL);
	if (!handle) {
		SLOGE("Failed to open notification binary");
		return 0;
	}

	CheckFile = (int(*)(void))(dlsym(handle, "CheckProfileFile"));
	if (!CheckFile) {
		SLOGE("Failed to open symbol CheckProfileFile");
        result = 0;
        goto err;
	}

	result = CheckFile();
	if (!result){
        SLOGD("checking file. device profile dose not exist.");
        result = -1;
        goto err;
	}

	base64cert = (unsigned char *)calloc(certSize*2, 1);
    if (!base64cert) {
        result = 0;
        goto err;
    }
	cert_svc_util_base64_encode(cert, certSize, base64cert, &base64certSize);

	CheckFunc = (int(*)(const unsigned char *, int))(dlsym(handle, "CheckDevice"));
	if (!CheckFunc) {
		SLOGE("Failed to open symbol CheckDevice");
        result = 0;
        goto err_ret_after_free;
	}

	result = CheckFunc(base64cert, base64certSize);
	SLOGD("Result of checking device : %d", result);

err_ret_after_free:
    free(base64cert);

err:
    dlclose(handle);
	return result;
}

int cert_svc_get_certificate_type(CERT_CONTEXT *ctx, int* cert_type)
{
	CERT_CONTEXT* context = NULL;
	int ret = CERT_SVC_ERR_NO_ERROR;

	if(!ctx || !cert_type)
	{
		SLOGE("Invalid prameters");
		return CERT_SVC_ERR_INVALID_PARAMETER;
	}

	if(!ctx->fileNames || !ctx->fileNames->filename)
	{
		SLOGE("Can not find root certificate path");
		return CERT_SVC_ERR_INVALID_PARAMETER;
	}

	context = cert_svc_cert_context_init();
	if(!context)
	{
		SLOGE("Out of memory");
		return CERT_SVC_ERR_MEMORY_ALLOCATION;
	}

	ret	= cert_svc_load_file_to_context(context, ctx->fileNames->filename);
	if(ret != CERT_SVC_ERR_NO_ERROR)
	{
		SLOGE("failed to load root certficiate");
		cert_svc_cert_context_final(context);
		return CERT_SVC_ERR_INVALID_CERTIFICATE;
	}

	ret = get_certificate_type(context, cert_type);

	cert_svc_cert_context_final(context);
	return ret;
}

int _cert_svc_verify_certificate_with_caflag(CERT_CONTEXT* ctx, int checkCAFlag, int checkSamsungCertFlag, int* validity)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	int cert_type = 0;
	unsigned char *cert = NULL;
	int size=0;
	int result = 0;

	if((ctx == NULL) || (ctx->certLink == NULL) || (ctx->certLink->certificate == NULL)) {
		SLOGE("[ERR][%s] Check your parameter. Cannot find certificate.", __func__);
		return CERT_SVC_ERR_INVALID_PARAMETER;
	}

	size = ctx->certLink->certificate->size;
	cert = (unsigned char *)calloc(size, 1);
    if (!cert)
        return CERT_SVC_ERR_MEMORY_ALLOCATION;
	memcpy(cert, ctx->certLink->certificate->data, size);

	if(ctx->certBuf == NULL) {
		SLOGE("[ERR][%s] Check your parameter. Cannot find certificate.", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}
	if(ctx->fileNames != NULL) {
		SLOGE("[ERR][%s] Check your parameter. fileNames field is NOT NULL.", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	/* memory allocation for root file path */
	if(!(ctx->fileNames = (cert_svc_filename_list*)malloc(sizeof(cert_svc_filename_list)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	if(!(ctx->fileNames->filename = (char*)malloc(sizeof(char) * CERT_SVC_MAX_FILE_NAME_SIZE))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(ctx->fileNames->filename, 0x00, CERT_SVC_MAX_FILE_NAME_SIZE);
	ctx->fileNames->next = NULL;

	/* call verify function */
	if((ret = _verify_certificate_with_caflag(ctx->certBuf, &(ctx->certLink), checkCAFlag, checkSamsungCertFlag, ctx->fileNames, validity)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to verify certificate.", __func__);
		goto err;
	}

	SECURE_LOGD("root cert path : %s", ctx->fileNames->filename);
	ret = cert_svc_get_certificate_type(ctx, &cert_type);
	if( ret != CERT_SVC_ERR_NO_ERROR){
		SLOGE("failed to cert_svc_get_certificate_type");
		goto err;
	}

	SLOGD("cert_type = %d", cert_type);
	if( cert_type == CERT_SVC_TYPE_TEST){
		SLOGD("Checking DUID");
		result = __is_certified_device(cert, size);
		if(result == -1){
			SLOGE("Device profile file does not exist in Device.");
			ret = CERT_SVC_ERR_INVALID_NO_DEVICE_PROFILE;
			goto err;
		}
		else if(result == 0){
			SLOGE("Device Unique ID (DUID) is not registered.");
			ret = CERT_SVC_ERR_INVALID_DEVICE_UNIQUE_ID;
			goto err;
		}
	}
	else{
		SLOGD("Cert type is not Test or Verity");
		SLOGD("Skip checking DUID");
	}

	SLOGD("[%s] Success to verify certificate.", __func__);

err:
	free(cert);
	return ret;
}



CERT_SVC_API
int cert_svc_add_certificate_to_store(const char* filePath, const char* location)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	char _filePath[CERT_SVC_MAX_FILE_NAME_SIZE];
	int pathSize = 0;

	if(filePath == NULL) {
		SLOGE("[ERR][%s] Check your parameter. Maybe file path is NULL.", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	pathSize = strlen(filePath);

	if (pathSize <= 0 || pathSize >= CERT_SVC_MAX_FILE_NAME_SIZE) {
		SLOGE("[ERR][%s] Check your parameter. Maybe file path is NULL.", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	memset(_filePath, 0x0, sizeof(_filePath));

	if(filePath[0] != '/') {	// not absolute path, this is regarded relative file path
		if (getcwd(_filePath, sizeof(_filePath))) {
			int cwdSize = 0;
			//just in case
			_filePath[sizeof(_filePath) - 1] = '\0';

			cwdSize = strlen(_filePath);

			if (cwdSize <=0 || (cwdSize + pathSize + 1) >= CERT_SVC_MAX_FILE_NAME_SIZE) {
				SLOGE("[ERR][%s] Check your parameter. Maybe file path is NULL.", __func__);
				ret = CERT_SVC_ERR_INVALID_OPERATION;
				goto err;
			}

			strncat(_filePath, "/", 1);
			strncat(_filePath, filePath, pathSize);

		} else {
			SLOGE("[ERR][%s] Check your parameter. Maybe file path is NULL.", __func__);
			ret = CERT_SVC_ERR_INVALID_OPERATION;
			goto err;
		}
	}
	else {
		strncpy(_filePath, filePath, pathSize);
	}

	ret = _add_certificate_to_store(_filePath, location);

	if(ret != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to store certificate, [%s]", __func__, _filePath);
		goto err;
	}
	SLOGD("[%s] Success to add certificate [%s].", __func__, filePath);

err:
	return ret;
}

CERT_SVC_API
int cert_svc_delete_certificate_from_store(const char* fileName, const char* location)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	if((fileName == NULL) || (fileName[0] == '/')) {
		SLOGE("[ERR][%s] Check your parameter. Maybe file name is NULL or is not single name.", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	ret = _delete_certificate_from_store(fileName, location);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to delete certificate, [%s]", __func__, fileName);
		goto err;
	}
	SLOGD("[%s] Success to delete certificate [%s].", __func__, fileName);

err:
	return ret;
}


CERT_SVC_API
int cert_svc_verify_package_certificate(CERT_CONTEXT* ctx, int* validity, const char* signatureFile)
{
	SLOGD("cert_svc_verify_package_certificate");
	int ca_cflag_check_false = 0;
	int samsung_cert_check_flag = 0;

	int ret = _cert_svc_verify_certificate_with_caflag(ctx, ca_cflag_check_false, samsung_cert_check_flag, validity);
	if(ret != CERT_SVC_ERR_NO_ERROR)
		return ret;

	int visibility = 0;
	ret = cert_svc_get_visibility(ctx, &visibility);
	if(ret != CERT_SVC_ERR_NO_ERROR)
		return ret;

	char* sig_file_name = NULL;
	if((sig_file_name = strstr(signatureFile, AUTHOR_SIGNATURE)) != NULL)
	{
		SLOGD("signature file : %s %d", sig_file_name, visibility);
		if(strncmp(sig_file_name, AUTHOR_SIGNATURE, strlen(sig_file_name)) == 0)
		{
			if(visibility != CERT_SVC_VISIBILITY_DEVELOPER)
			{
				SLOGE("Author signature signed as distributor signature. Invalid!");
				*validity = 0;
				return CERT_SVC_ERR_IN_AUTHOR_CASE_DISTRIBUTOR_CERT;//TCERT_SVC_ERR_INVALID_SIGNATURE;
			}
		}
	}
	else if((sig_file_name = strstr(signatureFile, DISTRIBUTOR_SIGNATURE)) != NULL)
	{
		SLOGD("signature file : %s %d", sig_file_name, visibility);
		if(strncmp(sig_file_name, DISTRIBUTOR_SIGNATURE, strlen(sig_file_name)) == 0)
		{
			if(visibility == CERT_SVC_VISIBILITY_DEVELOPER)
			{
				SLOGE("Distributor signature signed as author signature. Invalid!");
				*validity = 0;
				return CERT_SVC_ERR_IN_DISTRIBUTOR_CASE_AUTHOR_CERT;//CERT_SVC_ERR_INVALID_SIGNATURE;
			}
		}
	}

	return CERT_SVC_ERR_NO_ERROR;
}

CERT_SVC_API
int cert_svc_verify_package_signature(const char* signatureFile, const char* root_cert_path, const GList* refList)
{
	int ret = 0;
	ret = verify_package_signature_with_references(signatureFile, root_cert_path, refList);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		LOGE("Failed to verify signature!");
		return CERT_SVC_ERR_INVALID_SIGNATURE;
	}
	return CERT_SVC_ERR_NO_ERROR;
}


CERT_SVC_API
int cert_svc_verify_certificate(CERT_CONTEXT* ctx, int* validity)
{
	int ca_cflag_check_false = 0;
	int samsung_cert_check_flag = 0;
	return _cert_svc_verify_certificate_with_caflag(ctx, ca_cflag_check_false, samsung_cert_check_flag, validity);
}

CERT_SVC_API
int cert_svc_verify_certificate_with_caflag(CERT_CONTEXT* ctx, int* validity)
{
	int ca_cflag_check_true = 1;
	int samsung_cert_check_flag = 0;
	return _cert_svc_verify_certificate_with_caflag(ctx, ca_cflag_check_true, samsung_cert_check_flag, validity);
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
		SLOGE("[ERR][%s] Invalid parameter, please check your parameter", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	if((ret = _verify_signature(ctx->certBuf, message, msgLen, signature, algo, validity)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to verify signature.", __func__);
		goto err;
	}
	SLOGD("[%s] Success to verify signature.", __func__);

err:
	return ret;
}

CERT_SVC_API
int cert_svc_extract_certificate_data(CERT_CONTEXT* ctx)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	/* chec parameter */
	if(ctx == NULL) {
		SLOGE("[ERR][%s] Check your parameter.", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	/* check context */
	if(ctx->certBuf == NULL) {
		SLOGE("[ERR][%s] Cannot find certificate to be extracted.", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}
	if(ctx->certDesc != NULL) {
		SLOGE("[ERR][%s] certDesc is not NULL. cannot load content.", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	/* memory allocation of cert descriptor */
	if(!(ctx->certDesc = (cert_svc_cert_descriptor*)malloc(sizeof(cert_svc_cert_descriptor)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(ctx->certDesc, 0x00, sizeof(cert_svc_cert_descriptor));

	/* call extract function */
	if((ret = _extract_certificate_data(ctx->certBuf, ctx->certDesc)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to extract certificate data.", __func__);
		goto err;
	}
	SLOGD("[%s] Success to extract certificate.", __func__);

err:
	return ret;
}

CERT_SVC_API
int cert_svc_search_certificate(CERT_CONTEXT* ctx, search_field fldName, char* fldData)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	/* check parameter, fldName is unsigned int. It will never be negative */
	if((ctx == NULL) || (fldName > SEARCH_FIELD_END) || (fldData == NULL)) {
		SLOGE("[ERR][%s] Invalid parameter. Check your parameter", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	/* check conext */
	if(ctx->fileNames != NULL) {
		SLOGE("[ERR][%s] fileNames field already be used.", __func__);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}

	/* search specific field */
	if((ret = _search_certificate(&(ctx->fileNames), fldName, fldData)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to search certificate.", __func__);
		SLOGE("[ERR][%s] Fail to search certificate.", ctx->fileNames);
		goto err;
	}
	SLOGD("[%s] Success to search certificate(s).", __func__);

err:
	return ret;
}

CERT_SVC_API
CERT_CONTEXT* cert_svc_cert_context_init()
{
	CERT_CONTEXT* ctx = NULL;

	if(!(ctx = (CERT_CONTEXT*)malloc(sizeof(CERT_CONTEXT)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		return NULL;
	}

	ctx->certBuf = NULL;
	ctx->certDesc = NULL;
	ctx->certLink = NULL;
	ctx->fileNames = NULL;

	SLOGD("[%s] Success to initialize context.", __func__);

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

	SLOGD("[%s] Success to finalize context.", __func__);

err:
	return ret;
}

CERT_SVC_API
int cert_svc_load_buf_to_context(CERT_CONTEXT* ctx, unsigned char *buf)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	int size = 0;
    unsigned char *decodedBuf = NULL;
    int decodedSize = 0;

	/* check parameter */
	if((ctx == NULL) || (buf == NULL)) {
		SLOGE("[ERR][%s] context or buf is NULL.", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	/* memory allocation for ctx->certBuf */
	if(ctx->certBuf != NULL) {
		SLOGE("[ERR][%s] certBuf is already used. we cannot load buffer content.", __func__);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}
	if(!(ctx->certBuf = (cert_svc_mem_buff*)malloc(sizeof(cert_svc_mem_buff)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(ctx->certBuf, 0x00, sizeof(cert_svc_mem_buff));

	/* memory allocation for decoded string */
	size = strlen((char *)buf);
	decodedSize = ((size / 4) * 3) + 1;

	if(!(decodedBuf = (unsigned char *)malloc(sizeof(unsigned char) * decodedSize))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}

	/* decode */
	if((ret = cert_svc_util_base64_decode(buf, size, decodedBuf, &decodedSize)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to decode string, ret: [%d]", __func__, ret);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		free(decodedBuf);
		goto err;
	}

	/* load content to CERT_CONTEXT */
	ctx->certBuf->data = decodedBuf;
	ctx->certBuf->size = decodedSize;

	SLOGD("[%s] Success to load certificate buffer content to context.", __func__);

err:
	return ret;
}

CERT_SVC_API
int cert_svc_load_file_to_context(CERT_CONTEXT* ctx, const char* filePath)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	/* check parameter */
	if((ctx == NULL) || (filePath == NULL)) {
		SLOGE("[ERR][%s] context or file path is NULL.", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	/* memory allocation for (*ctx)->certBuf */
	if(ctx->certBuf != NULL) {
		SLOGE("[ERR][%s] certBuf is already used. we cannot load file.", __func__);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}
	if(!(ctx->certBuf = (cert_svc_mem_buff*)malloc(sizeof(cert_svc_mem_buff)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(ctx->certBuf, 0x00, sizeof(cert_svc_mem_buff));

	/* get content to (*ctx)->certBuf */
	if((ret = cert_svc_util_load_file_to_buffer(filePath, ctx->certBuf)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to load file, filepath: [%s], ret: [%d]", __func__, filePath, ret);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}
	
	SLOGD("[%s] Success to load certificate file content to context.", __func__);

err:
	return ret;
}

CERT_SVC_API
int cert_svc_push_buf_into_context(CERT_CONTEXT *ctx, unsigned char* buf)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_linked_list* cur = NULL;
	cert_svc_linked_list* new = NULL;
	int size = 0;
	unsigned char* decodedBuf = NULL;
    int decodedSize = 0;

	/* check parameter */
	if((ctx == NULL) || (buf == NULL)) {
		SLOGE("[ERR][%s] context or buf is NULL.", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	/* memory alloction new item */
	if(!(new = (cert_svc_linked_list*)malloc(sizeof(cert_svc_linked_list)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	if(!(new->certificate = (cert_svc_mem_buff*)malloc(sizeof(cert_svc_mem_buff)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		free(new);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}

	/* memory allocation for decoded string */
	size = strlen((char *)buf);
	decodedSize = ((size / 4) * 3) + 1;

	if(!(decodedBuf = (unsigned char *)malloc(sizeof(unsigned char) * decodedSize))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		release_cert_list(new);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}

	/* decode */
	if((ret = cert_svc_util_base64_decode(buf, size, decodedBuf, &decodedSize)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to decode string, ret: [%d]", __func__, ret);
		release_cert_list(new);
		free(decodedBuf);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}

	/* load content to CERT_CONTEXT */
	new->certificate->data = decodedBuf;
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
	
	SLOGD("[%s] Success to push certificate buffer content to context.", __func__);

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
		SLOGE("[ERR][%s] context or file path is NULL.", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	/* memory alloction new item */
	if(!(new = (cert_svc_linked_list*)malloc(sizeof(cert_svc_linked_list)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(new, 0x00, sizeof(cert_svc_linked_list));
	if(!(new->certificate = (cert_svc_mem_buff*)malloc(sizeof(cert_svc_mem_buff)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		free(new);
		goto err;
	}
	memset(new->certificate, 0x00, sizeof(cert_svc_mem_buff));

	/* get content to ctx->certBuf */
	if((ret = cert_svc_util_load_file_to_buffer(filePath, new->certificate)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to load file, filepath: [%s], ret: [%d]", __func__, filePath, ret);
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
	
	SLOGD("[%s] Success to push certificate file content to context.", __func__);

err:
	return ret;
}

CERT_SVC_API
int cert_svc_load_PFX_file_to_context(CERT_CONTEXT* ctx, unsigned char** privateKey, int* priKeyLen, const char* filePath, char* passPhrase)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	/* check parameter */
	if((ctx == NULL) || (filePath == NULL)) {
		SLOGE("[ERR][%s] context or file path is NULL.", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	/* memory allocation for ctx->certBuf */
	if(ctx->certBuf != NULL) {
		SLOGE("[ERR][%s] certBuf is already used. we cannot load file.", __func__);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}
	if(!(ctx->certBuf = (cert_svc_mem_buff*)malloc(sizeof(cert_svc_mem_buff)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(ctx->certBuf, 0x00, sizeof(cert_svc_mem_buff));

	/* get content to ctx->certBuf */
	if((ret = cert_svc_util_load_PFX_file_to_buffer(filePath, ctx->certBuf, &ctx->certLink, privateKey, priKeyLen, passPhrase)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to load file, filepath: [%s], ret: [%d]", __func__, filePath, ret);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}
	
	SLOGD("[%s] Success to load certificate file content to context.", __func__);

err:
	return ret;
}

#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
CERT_SVC_API
int cert_svc_check_ocsp_status(CERT_CONTEXT* ctx, const char* uri)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_linked_list** certList=NULL;

		/* check revocation status */
	/* check parameter */
	if((ctx == NULL) || (ctx->certBuf == NULL)) {
		SLOGE("[ERR][%s] certBuf must have value.", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	/* check revocation status */
	if(ctx->certLink != NULL) {
		certList = &(ctx->certLink);
	}
	if((ret = _check_ocsp_status(ctx->certBuf, certList, uri)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to check revocation status.", __func__);
		goto err;
	}

err:
	return ret;
}
#endif

CERT_SVC_API
char* cert_svc_get_certificate_crt_file_path(void)
{
	return CRT_FILE_PATH;
}

CERT_SVC_API
int cert_svc_get_visibility(CERT_CONTEXT *ctx, int* visibility)
{
	CERT_CONTEXT* context = NULL;
	int ret = CERT_SVC_ERR_NO_ERROR;

	if(!ctx || !visibility)
	{
		SLOGE("Invalid prameters");
		return CERT_SVC_ERR_INVALID_PARAMETER;
	}

	if(!ctx->fileNames || !ctx->fileNames->filename)
	{
		SLOGE("Can not find root certificate path");
		return CERT_SVC_ERR_INVALID_PARAMETER;
	}

	context = cert_svc_cert_context_init();
	if(!context)
	{
		SLOGE("Out of memory");
		return CERT_SVC_ERR_MEMORY_ALLOCATION;
	}

	ret	= cert_svc_load_file_to_context(context, ctx->fileNames->filename);
	if(ret != CERT_SVC_ERR_NO_ERROR)
	{
		SLOGE("failed to load root certficiate");
		cert_svc_cert_context_final(context);
		return CERT_SVC_ERR_INVALID_CERTIFICATE;
	}

	ret = get_visibility(context, visibility);

	cert_svc_cert_context_final(context);
	return ret;
}


CERT_SVC_API
int cert_svc_get_visibility_by_root_certificate(const char* base64_encoded_data, int data_len, int* visibility)
{
	if(!base64_encoded_data|| !data_len)
	{
		return CERT_SVC_ERR_INVALID_PARAMETER;
	}

	int ret = get_visibility_by_certificate((const unsigned char *)base64_encoded_data, data_len, visibility);
	if(ret != CERT_SVC_ERR_NO_ERROR)
	{
		SLOGE("Failed to get_visibility :%d", ret);
		return ret;
	}
	return CERT_SVC_ERR_NO_ERROR;
}

CERT_SVC_API
int cert_svc_util_parse_name_fld_data(unsigned char* str, cert_svc_name_fld_data* fld)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	ret = parse_name_fld_data(str, fld);
	return ret;
}

void hex_encoder(char* src, int srcLen, char* out)
{
	int i = 0;
	unsigned char cLow = 0;
	unsigned char cHigh = 0;

	for(i = 0 ; i < srcLen ; i++)
	{
		cLow = src[i] & 0x0f;
		cHigh = (src[i] >> 4) & 0x0f;
		if(cLow <= 9)
			out[i*2+1] = cLow + '0';
		else
			out[i*2+1] = cLow - 10 + 'A';

		if( cHigh <= 9)
			out[i*2] = cHigh + '0';
		else
			out[i*2] = cHigh - 10 + 'A';
	}

}

CERT_SVC_API
int cert_svc_verify_package_signature_file(const char* sigfileFullPath, const char* rootCertPath)
{
	int ret = verify_package_signature_file(sigfileFullPath, rootCertPath);
	if (ret != CERT_SVC_ERR_NO_ERROR)
		SLOGE("Failed to verify package signature %d", ret);

	return ret;
}

CERT_SVC_API
int cert_svc_verify_package_signature_with_references(const char* sigfileFullPath, const char* rootCertPath, const GList* refList)
{
	int ret = verify_package_signature_with_references(sigfileFullPath, rootCertPath, refList);
	if (ret != CERT_SVC_ERR_NO_ERROR)
		SLOGE("Failed to verify package signature %d", ret);

	return ret;
}
