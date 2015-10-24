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

#include <openssl/pkcs12.h>
#include <openssl/pem.h>

#include "cert-service.h"
#include "cert-service-util.h"
#include "cert-service-debug.h"
#include "cert-service-process.h"

#include <libxml/parser.h>
#include <libxml/tree.h>

#ifndef CERT_SVC_API
#define CERT_SVC_API	__attribute__((visibility("default")))
#endif

#define CERT_BODY_PREFIX  "-----BEGIN CERTIFICATE-----"
#define CERT_BODY_SUFIX   "-----END CERTIFICATE-----"
#define ICERT_BODY_PREFIX "-----BEGIN TRUSTED CERTIFICATE-----"
#define ICERT_BODY_SUFIX  "-----END TRUSTED CERTIFICATE-----"

/* Tables for base64 operation */
static const unsigned char base64Table[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', //  0 ~ 15
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', // 16 ~ 31
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', // 32 ~ 47
	'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'  // 48 ~ 63
};
static int base64DecodeTable[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //   0 ~  15
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //  16 ~  31
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, //  32 ~  47
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, //  48 ~  63
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, //  64 ~  79
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, //  80 ~  95
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, //  96 ~ 111
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, // 112 ~ 127
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 128 ~ 143
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 144 ~ 159
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 160 ~ 175
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 176 ~ 191
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 192 ~ 207
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 208 ~ 223
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 224 ~ 239
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1  // 240 ~ 255
};

int get_content_into_buf_PEM(unsigned char* content, cert_svc_mem_buff* cert)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	char *startPEM, *endPEM;
	unsigned char* original = NULL;
	long size = 0;
	unsigned char* decoded = NULL;
	int decodedSize = 0;
	int i = 0, j = 0;

	if(!content) {
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}
	startPEM = strstr((const char *)content, CERT_BODY_PREFIX);
	startPEM = (startPEM) ? startPEM + strlen(CERT_BODY_PREFIX) : NULL;
	endPEM = strstr((const char *)content, CERT_BODY_SUFIX);
	if(!startPEM || !endPEM) {
		startPEM = strstr((const char *)content, ICERT_BODY_PREFIX);
		startPEM = (startPEM) ? startPEM + strlen(ICERT_BODY_PREFIX) : NULL;
		endPEM = strstr((const char *)content, ICERT_BODY_SUFIX);
	}
	if(!startPEM || !endPEM) {
		ret = CERT_SVC_ERR_UNKNOWN_ERROR;
		goto err;
	}
	else {
		++startPEM;
		--endPEM;
		size = (long)endPEM - (long)startPEM;
	}

	if(!(original = (unsigned char *)malloc(sizeof(unsigned char) * (size + 1)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(original, 0x00, (size + 1));

	for(i = 0, j = 0; i < size; i++) {
		if(startPEM[i] != '\n')
			original[j++] = startPEM[i];
	}

	size = strlen((char *)original);
	decodedSize = ((size / 4) * 3) + 1;

	if(!(decoded = (unsigned char *)malloc(sizeof(unsigned char) * decodedSize))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(decoded, 0x00, decodedSize);
	if((ret = cert_svc_util_base64_decode(original, size, decoded, &decodedSize)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to base64 decode.", __func__);
		free(decoded);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}

	cert->data = decoded;
	cert->size = decodedSize;

err:
    free(original);

	return ret;
}

int get_content_into_buf_DER(unsigned char* content, cert_svc_mem_buff* cert)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	unsigned char* certData = NULL;

	certData = (unsigned char*)malloc(sizeof(unsigned char) * (cert->size));
	if(certData == NULL) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}

	memcpy(certData, content, cert->size);
	cert->data = certData;

err:
	return ret;
}

int cert_svc_util_get_file_size(const char* filepath, unsigned long int* length)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	FILE* fp_in = NULL;

	if(!(fp_in = fopen(filepath, "r"))) {
		SLOGE("[ERR][%s] Fail to open file, [%s]", __func__, filepath);
		ret = CERT_SVC_ERR_FILE_IO;
		goto err;
	}

	fseek(fp_in, 0L, SEEK_END);
	(*length) = ftell(fp_in);

err:
	if(fp_in != NULL)
		fclose(fp_in);

	return ret;
}

/* The dark side of cert-svc. */
int cert_svc_util_get_extension(const char* filePath, cert_svc_mem_buff* certBuf) {
    int ret = CERT_SVC_ERR_NO_ERROR;
    FILE *in = NULL;
    X509 *x = NULL;

    if ((in = fopen(filePath, "r")) == NULL) {
        SLOGE("[ERR] Error opening file %s", filePath);
        ret = CERT_SVC_ERR_FILE_IO;
        goto end;
    }

    if ((x = PEM_read_X509(in, NULL, NULL, NULL)) != NULL) {
        strncpy(certBuf->type, "PEM", sizeof(certBuf->type));
        goto end;
    }

    fseek(in, 0L, SEEK_SET);

    if ((x = PEM_read_X509_AUX(in, NULL, NULL, NULL)) != NULL) {
        strncpy(certBuf->type, "PEM", sizeof(certBuf->type));
        goto end;
    }

    fseek(in, 0L, SEEK_SET);

    if ((x = d2i_X509_fp(in, NULL)) != NULL) {
        strncpy(certBuf->type, "DER", sizeof(certBuf->type));
        goto end;
    }

    SLOGE("[ERR] Unknown file type: %s", filePath);
    ret = CERT_SVC_ERR_FILE_IO;

end:
    if (in && fclose(in)) {
        SLOGE("[ERR] Fail in fclose.");
        ret = CERT_SVC_ERR_FILE_IO;
    }
    X509_free(x);
    return ret;
}

int cert_svc_util_load_file_to_buffer(const char* filePath, cert_svc_mem_buff* certBuf)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	// open file and get content
	FILE* fp_in = NULL;
	unsigned char* content = NULL;
	unsigned long int fileSize = 0;

	/* get file size */
	if((ret = cert_svc_util_get_file_size(filePath, &fileSize)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to get file size, [%s]", __func__, filePath);
		goto err;
	}
	certBuf->size = fileSize;

	/* open file and write to buffer */
	if(!(fp_in = fopen(filePath, "rb"))) {
		SLOGE("[ERR][%s] Fail to open file, [%s]", __func__, filePath);
		ret = CERT_SVC_ERR_FILE_IO;
		goto err;
	}

	if(!(content = (unsigned char*)malloc(sizeof(unsigned char) * (unsigned int)(fileSize + 1)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
    memset(content, 0x00, (fileSize + 1));  //ensuring that content[] will be NULL terminated
	if(fread(content, sizeof(unsigned char), fileSize, fp_in) != fileSize) {
		SLOGE("[ERR][%s] Fail to read file, [%s]", __func__, filePath);
		ret = CERT_SVC_ERR_FILE_IO;
		goto err;
	}
    content[fileSize] = 0; // insert null on the end to make null-terminated string

	/* find out certificate type */
	memset(certBuf->type, 0x00, 4);
    if (cert_svc_util_get_extension(filePath, certBuf) != CERT_SVC_ERR_NO_ERROR) {
        SLOGE("[ERR] cert_svc_util_get_extension failed to identify %s", filePath);
        ret = CERT_SVC_ERR_FILE_IO;
        goto err;
    }

	/* load file into buffer */
	if(!strncmp(certBuf->type, "PEM", sizeof(certBuf->type))) {	// PEM format
		if((ret = get_content_into_buf_PEM(content, certBuf)) != CERT_SVC_ERR_NO_ERROR) {
			SLOGE("[ERR][%s] Fail to load file to buffer, [%s]", __func__, filePath);
			goto err;
		}
	}
	else if(!strncmp(certBuf->type, "DER", sizeof(certBuf->type))) {	// DER format
		if((ret = get_content_into_buf_DER(content, certBuf)) != CERT_SVC_ERR_NO_ERROR) {
			SLOGE("[ERR][%s] Fail to load file to buffer, [%s]", __func__, filePath);
			goto err;
		}
	}

err:
	if(fp_in != NULL)
		fclose(fp_in);

	if(content != NULL)
		free(content);

	return ret;
}

int push_cert_into_linked_list(cert_svc_linked_list** certLink, X509* popedCert)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_linked_list* cur = NULL;
	cert_svc_linked_list* newNode = NULL;
	unsigned char* pCert = NULL;
	unsigned char* bufCert = NULL;
	int certLen = 0;

	if(!(newNode = (cert_svc_linked_list*)malloc(sizeof(cert_svc_linked_list)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	if(!(newNode->certificate = (cert_svc_mem_buff*)malloc(sizeof(cert_svc_mem_buff)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		free(newNode);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}

	/* get certificate data and store in certLink */
	if((certLen = i2d_X509(popedCert, NULL)) < 0) {
		SLOGE("[ERR][%s] Fail to convert certificate.", __func__);
		release_cert_list(newNode);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}
	if(!(bufCert = (unsigned char*)malloc(sizeof(unsigned char) * certLen))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		release_cert_list(newNode);
		goto err;
	}
	pCert = bufCert;
	i2d_X509(popedCert, &pCert);

	newNode->certificate->data = bufCert;
	newNode->certificate->size = certLen;
	newNode->next = NULL;

	if(NULL == *certLink) {	// first item
		*certLink = newNode;
	}
	else {
	    /* attach to linked list */
	    cur = *certLink;
		while(cur->next)
			cur = cur->next;
		cur->next = newNode;
	}

err:
	return ret;
}

int cert_svc_util_load_PFX_file_to_buffer(const char* filePath, cert_svc_mem_buff* certBuf, cert_svc_linked_list** certLink, unsigned char** privateKey, int* priKeyLen, char* passPhrase)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	// related pkcs12 and x509
	EVP_PKEY* pkey = NULL;
	X509* cert = NULL;
	STACK_OF(X509)* ca = NULL;
	X509* popedCert = NULL;
	PKCS12* p12 = NULL;
	// open file and get content
	FILE* fp_in = NULL;
	// put informations to context
	unsigned char* pCert = NULL;
	unsigned char* bufCert = NULL;
	int certLen = 0;
	unsigned char* pPrikey = NULL;
	unsigned char* bufPrikey = NULL;
	int prikeyLen = 0;

	OpenSSL_add_all_algorithms();

	/* open file and write to buffer */
	if(!(fp_in = fopen(filePath, "rb"))) {
		SLOGE("[ERR][%s] Fail to open file, [%s]", __func__, filePath);
		ret = CERT_SVC_ERR_FILE_IO;
		goto err;
	}
	if(!(p12 = d2i_PKCS12_fp(fp_in, NULL))) {
		SLOGE("[ERR][%s] Fail to get certificate data.", __func__);
		ret = CERT_SVC_ERR_INVALID_CERTIFICATE;
		goto err;
	}

	/* parse PKCS#12 certificate */
	if((ret = PKCS12_parse(p12, passPhrase, &pkey, &cert, &ca)) != 1) {
		SLOGE("[ERR][%s] Fail to parse PKCS#12 certificate.", __func__);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}
	ret = CERT_SVC_ERR_NO_ERROR;
	/* find out certificate type */
	memset(certBuf->type, 0x00, 4);
	strncpy(certBuf->type, "PFX", sizeof(certBuf->type));

	/* load certificate into buffer */
	if((certLen = i2d_X509(cert, NULL)) < 0) {
		SLOGE("[ERR][%s] Fail to convert certificate.", __func__);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}
	if(!(bufCert = (unsigned char*)malloc(sizeof(unsigned char) * certLen))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	pCert = bufCert;
	i2d_X509(cert, &pCert);

	certBuf->data = bufCert;
	certBuf->size = certLen;

	/* load private key into buffer */
	if((prikeyLen = i2d_PrivateKey(pkey, NULL)) < 0) {
		SLOGE("[ERR][%s] Fail to convert private key.", __func__);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}
	SLOGE("[LOG] private key length: [%d]", prikeyLen);
	if(!(bufPrikey = (unsigned char*)malloc(sizeof(unsigned char) * prikeyLen))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	pPrikey = bufPrikey;
	i2d_PrivateKey(pkey, &pPrikey);

	(*privateKey) = bufPrikey;
	(*priKeyLen) = prikeyLen;

	/* load ca certificates(if exists) into buffer */
	while((popedCert = sk_X509_pop(ca)) != NULL) {
		if((ret = push_cert_into_linked_list(certLink, popedCert)) != CERT_SVC_ERR_NO_ERROR) {
			SLOGE("[ERR][%s] Fail to make linked list.", __func__);
			goto err;
		}
	}

err:
	if(fp_in != NULL)
		fclose(fp_in);
	if(p12 != NULL)
		PKCS12_free(p12);
	if(cert != NULL)
		X509_free(cert);
	if(pkey != NULL)
		EVP_PKEY_free(pkey);
	if(ca != NULL)
		sk_X509_pop_free(ca, X509_free);
	//EVP_cleanup();

	return ret;
}

CERT_SVC_API
int cert_svc_util_base64_encode(const unsigned char *in, int inLen, unsigned char *out, int *outLen)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	int inputLen = 0, i = 0;
	const unsigned char *cur = NULL;

	if((in == NULL) || (inLen < 1)) {
		SLOGE("[ERR][%s] Check your parameter.", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	cur = in;
	inputLen = inLen;

	/* encode data */
	while(inputLen > 2) {
		out[i++] = base64Table[cur[0] >> 2];
		out[i++] = base64Table[((cur[0] & 0x03) << 4) + (cur[1] >> 4)];
		out[i++] = base64Table[((cur[1] & 0x0f) << 2) + (cur[2] >> 6)];
		out[i++] = base64Table[cur[2] & 0x3f];

		cur += 3;
		inputLen -= 3;
	}

	/* determine tail of output string */
	if(inputLen != 0) {	// 1 or 2
		out[i++] = base64Table[cur[0] >> 2];
		if(inputLen > 1) {	// 2
			out[i++] = base64Table[((cur[0] & 0x03) << 4) + (cur[1] >> 4)];
			out[i++] = base64Table[(cur[1] & 0x0f) << 2];
			out[i++] = '=';
		}
		else {	// 1
			out[i++] = base64Table[(cur[0] & 0x03) << 4];
			out[i++] = '=';
			out[i++] = '=';
		}
	}

	out[i] = '\0';
	(*outLen) = i;

err:
	return ret;
}

CERT_SVC_API
int cert_svc_util_base64_decode(const unsigned char *in, int inLen, unsigned char *out, int* outLen)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	int inputLen = 0, i = 0, j = 0, tail = 0;
	const unsigned char *cur = NULL;
	unsigned char tmpBuf[4];

	if((in == NULL) || (inLen < 1)) {
		SLOGE("[ERR][%s] Check your parameter.", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	cur = in;
	inputLen = inLen;
	memset(tmpBuf, 0x00, 4);

	/* decode data */
	while(inputLen > 1) {
		for(j = 0; j < 4; j++) {
			if(cur[j] == '=') {
				tail++;
				tmpBuf[j] = 0x00;
			}
			else
				tmpBuf[j] = (unsigned char)base64DecodeTable[(int)cur[j]];
		}

		out[i++] = ((tmpBuf[0] & 0x3f) << 2) + ((tmpBuf[1] & 0x30) >> 4);
		out[i++] = ((tmpBuf[1] & 0x0f) << 4) + ((tmpBuf[2] & 0x3c) >> 2);
		out[i++] = ((tmpBuf[2] & 0x03) << 6) + (tmpBuf[3] & 0x3f);

		cur += 4;
		inputLen -= 4;

		memset(tmpBuf, 0x00, 4);
	}

	i -= tail;
	out[i] = '\0';
	(*outLen) = i;

err:
	return ret;
}

// fingerprint format - AA:BB:CC:DD:EE...
// cert - der(binary) format
int get_certificate_fingerprint(const unsigned char *cert, int cert_size, char** fingerprint)
{
	X509* x509Cert = NULL;
	unsigned char x509_fingerprint[EVP_MAX_MD_SIZE] = {0};
	char uniformedFingerprint[EVP_MAX_MD_SIZE * 3] = {0};
	int fp_len = 0;
	char buff[8] = {0};
	unsigned int x509_length = 0;
	unsigned int i = 0;

	if(!d2i_X509(&x509Cert, &cert, cert_size))
	{
		SLOGE("d2i_x509 failed!");
		*fingerprint = NULL;
		return CERT_SVC_ERR_INVALID_CERTIFICATE;
	}

	if(!X509_digest(x509Cert, EVP_sha1(), x509_fingerprint, &x509_length))
	{
		SLOGE("X509_digest failed");
		X509_free(x509Cert);
		*fingerprint = NULL;
		return CERT_SVC_ERR_INVALID_CERTIFICATE;
	}

	for(i = 0; i < x509_length; i++)
	{
		snprintf(buff, sizeof(buff), "%02X:", x509_fingerprint[i]);
		strncat(uniformedFingerprint, buff, 3);
	}
	uniformedFingerprint[x509_length * 3 - 1] = 0; // remove last :
	fp_len = strlen(uniformedFingerprint);

	*fingerprint = (char*)calloc(sizeof(char), fp_len + 1);
	if(*fingerprint == NULL)
	{
		SLOGE("Failed to allocate memory");
		X509_free(x509Cert);
		*fingerprint = NULL;
		return CERT_SVC_ERR_MEMORY_ALLOCATION;
	}

	memcpy(*fingerprint, uniformedFingerprint, fp_len + 1);

	SLOGD("fingerprint : %s", *fingerprint);

	X509_free(x509Cert);

	return CERT_SVC_ERR_NO_ERROR;
}

int get_visibility_by_fingerprint(const char* fingerprint, int* visibility)
{
	SLOGD("fingerprint : %s", fingerprint);
	int ret = 0;
	xmlChar *xmlPathDomainPlatform = (xmlChar*) "tizen-platform";
	xmlChar *xmlPathDomainPublic = (xmlChar*) "tizen-public";
	xmlChar *xmlPathDomainPartner = (xmlChar*) "tizen-partner";
	xmlChar *xmlPathDomainDeveloper = (xmlChar*) "tizen-developer";

	/*   load file */
	xmlDocPtr doc = xmlParseFile("/usr/share/wrt-engine/fingerprint_list.xml");
	if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL))
	{
		SLOGE("Failed to prase fingerprint_list.xml");
		return CERT_SVC_ERR_FILE_IO;
	}

	xmlNodePtr curPtr = xmlFirstElementChild(xmlDocGetRootElement(doc));
	if(curPtr == NULL)
	{
		SLOGE("Can not find root");
		xmlFreeDoc(doc);
		return CERT_SVC_ERR_FILE_IO;
	}

	while(curPtr != NULL)
	{
		xmlAttr* attr = curPtr->properties;
		if(!attr->children || !attr->children->content)
		{
			SLOGE("Failed to get fingerprints from list");
			ret = CERT_SVC_ERR_NO_ROOT_CERT;
			goto out;
		}

		xmlChar* strLevel = attr->children->content;
		xmlNodePtr FpPtr = xmlFirstElementChild(curPtr);

		/*
		if(FpPtr == NULL)
		{
			SLOGE("Could not find fingerprint");
			ret = CERT_SVC_ERR_NO_ROOT_CERT;
			goto out;
		}
		*/

		while(FpPtr)
		{
			xmlChar *content = xmlNodeGetContent(FpPtr);
			if(xmlStrcmp(content, (xmlChar*)fingerprint) == 0)
			{
				SLOGD("fingerprint : %s are %s", content, strLevel);
				if(!xmlStrcmp(strLevel, xmlPathDomainPlatform)){
					*visibility =  CERT_SVC_VISIBILITY_PLATFORM;
					ret = CERT_SVC_ERR_NO_ERROR;
					goto out;
				}
				else if(!xmlStrcmp(strLevel, xmlPathDomainPublic)){
					*visibility = CERT_SVC_VISIBILITY_PUBLIC;
					ret = CERT_SVC_ERR_NO_ERROR;
					goto out;
				}
				else if(!xmlStrcmp(strLevel, xmlPathDomainPartner)){
					*visibility = CERT_SVC_VISIBILITY_PARTNER;
					ret = CERT_SVC_ERR_NO_ERROR;
					goto out;
				}
				else if(!xmlStrcmp(strLevel, xmlPathDomainDeveloper)){
					*visibility = CERT_SVC_VISIBILITY_DEVELOPER;
					ret = CERT_SVC_ERR_NO_ERROR;
					goto out;
				}
			}
			FpPtr = xmlNextElementSibling(FpPtr);
		}
		curPtr = xmlNextElementSibling(curPtr);
	}

	SLOGE("Could not find fingerrpint");
	
	xmlFreeDoc(doc);
	return CERT_SVC_ERR_NO_ROOT_CERT;

out:
	xmlFreeDoc(doc);
	return ret;
}

int get_type_by_fingerprint(const char* fingerprint, int* cert_type)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	xmlChar *xmlPathDomainTest = (xmlChar*) "tizen-test";
	xmlChar *xmlPathDomainVerify = (xmlChar*) "tizen-verify";
	xmlChar *xmlPathDomainStore = (xmlChar*) "tizen-store";

	/*	 load file */
	xmlDocPtr doc = xmlParseFile("/usr/share/wrt-engine/fingerprint_list.xml");
	if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL))
	{
		SLOGE("Failed to prase fingerprint_list.xml");
		return CERT_SVC_ERR_FILE_IO;
	}

	xmlNodePtr curPtr = xmlFirstElementChild(xmlDocGetRootElement(doc));
	if(curPtr == NULL)
	{
		SLOGE("Can not find root");
		xmlFreeDoc(doc);
		return CERT_SVC_ERR_FILE_IO;
	}

	while(curPtr != NULL)
	{
		xmlAttr* attr = curPtr->properties;
		if(!attr->children || !attr->children->content)
		{
			SLOGE("Failed to get fingerprints from list");
			ret = CERT_SVC_ERR_NO_ROOT_CERT;
			goto out;
		}

		xmlChar* strLevel = attr->children->content;
		xmlNodePtr FpPtr = xmlFirstElementChild(curPtr);

		while(FpPtr)
		{
			xmlChar *content = xmlNodeGetContent(FpPtr);
			if(xmlStrcmp(content, (xmlChar*)fingerprint) == 0)
			{
				SLOGD("fingerprint : %s matched %s", content, strLevel);
				if(!xmlStrcmp(strLevel, xmlPathDomainTest)){
					*cert_type = CERT_SVC_TYPE_TEST;
					ret = CERT_SVC_ERR_NO_ERROR;
					goto out;
				}
				else if(!xmlStrcmp(strLevel, xmlPathDomainVerify)){
					*cert_type = CERT_SVC_TYPE_VERIFY;
					ret = CERT_SVC_ERR_NO_ERROR;
					goto out;
				}
				else if(!xmlStrcmp(strLevel, xmlPathDomainStore)){
					*cert_type = CERT_SVC_TYPE_STORE;
					ret = CERT_SVC_ERR_NO_ERROR;
					goto out;
				}
			}
			FpPtr = xmlNextElementSibling(FpPtr);
		}
		curPtr = xmlNextElementSibling(curPtr);
	}

	SLOGD("Could not find fingerprint");
	xmlFreeDoc(doc);
	*cert_type = CERT_SVC_TYPE_NO_TYPE;
	return CERT_SVC_ERR_NO_ERROR;

out:
	xmlFreeDoc(doc);
	return ret;
}


// expect input cert data is base64 encoded format
int get_visibility_by_certificate(const unsigned char *cert_data, int data_len, int* visibility)
{
	if(!cert_data || !data_len)
	{
		return CERT_SVC_ERR_INVALID_PARAMETER;
	}

	int decodedSize = ((data_len / 4) * 3) + 1;
	unsigned char *decoded = NULL;
	char *fingerprint = NULL;
	int ret = CERT_SVC_ERR_NO_ERROR;

	if(!(decoded = (unsigned char *)malloc(sizeof(unsigned char) * decodedSize))) {
		SLOGE("Fail to allocate memory.");
		return CERT_SVC_ERR_MEMORY_ALLOCATION;
	}
	memset(decoded, 0x00, decodedSize);

	if((ret = cert_svc_util_base64_decode(cert_data, data_len, decoded, &decodedSize)) != CERT_SVC_ERR_NO_ERROR)
	{
		SLOGE("Failed to decode data %d", ret);
		free(decoded);
		return ret;
	}

	ret = get_certificate_fingerprint(decoded, decodedSize, &fingerprint);
	if(ret != CERT_SVC_ERR_NO_ERROR)
	{
		SLOGE("Can not get fingerprint! %d", ret);
		return ret;
	}
	
	ret = get_visibility_by_fingerprint(fingerprint, visibility);
	if(ret != CERT_SVC_ERR_NO_ERROR)
	{
		SLOGE("Can not find visibility %d", ret);
		return ret;
	}

	free(decoded);
	free(fingerprint);
	return CERT_SVC_ERR_NO_ERROR;
}
