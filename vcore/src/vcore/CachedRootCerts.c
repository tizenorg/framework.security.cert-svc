/**
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
/*
 * @file        pkcs12.h
 * @author      Jacek Migacz (j.migacz@samsung.com)
 * @version     1.0
 * @brief       PKCS#12 container manipulation routines.
 */
#ifndef TIZEN_FEATURE_CERT_SVC_STORE_CAPABILITY
#define _GNU_SOURCE
#define  _CERT_SVC_VERIFY_PKCS12

#include <cert-service.h>
#include "cert-service-util.h"
#include <cert-svc/cerror.h>
#include <vcore/CachedRootCerts.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <dlfcn.h>
#include <dirent.h>
#include <dlog.h>
#include <dpl/log/wrt_log.h>

#define SYSCALL(call) while(((call) == -1) && (errno == EINTR))

#define CERTSVC_STORAGE_ROOT_DIR  "/opt/etc/ssl/certs/"
#define CERTSVC_SSL_ROOT_DIR      "/opt/share/cert-svc/"
#define CERTSVC_STORAGE_ROOT_FILE "storage-root"

#define CERTSVC_STORAGE_SYSTEM_PATH CERTSVC_SSL_ROOT_DIR "/" CERTSVC_STORAGE_ROOT_FILE

static const char  CERTSVC_STORAGE_KEY_ALIAS[] = "alias";
static const char  CERTSVC_STORAGE_KEY_PATH[]  = "path";

gboolean keyfile_check(const char *pathname) {
  int result;
  if(access(pathname, F_OK | R_OK | W_OK) == 0)
    return TRUE;
  SYSCALL(result = creat(pathname, S_IRUSR | S_IWUSR));
  if (result != -1) {
      result = close(result);
      if(result == -1)
        LOGD("Failed to close, errno : %d",  errno);
      return TRUE;
  } else {
      return FALSE;
  }
}

GKeyFile *keyfile_load(const char *pathname) {
  GKeyFile *keyfile;
  GError *error;

  if(!keyfile_check(pathname))
    return NULL;
  keyfile = g_key_file_new();
  error = NULL;
  if(!g_key_file_load_from_file(keyfile, pathname, G_KEY_FILE_KEEP_COMMENTS, &error)) {
    g_key_file_free(keyfile);
    return NULL;
  }
  return keyfile;
}

char* get_complete_path(const char *str1, char *str2) {

	size_t str1_len = strlen(str1);
	char *result = NULL;
	int as_result;

	if (str1[str1_len - 1] != '/') {
		as_result = asprintf(&result, "%s/%s", str1, str2);
	} else {
		as_result = asprintf(&result, "%s%s", str1, str2);
	}

	if(result != NULL){
		LOGD("LOGDEBUG: [path=%s]]", result);
	}

	if (as_result >= 0)
		return result;
	else
		return NULL;
}

char* load_keyfile(GKeyFile **keyfile, int *result) {

	char* updatePath = CERTSVC_STORAGE_SYSTEM_PATH;
	*result = CERTSVC_SUCCESS;
	struct stat fileAccess;

	/* In some scenario, we might get keyfile filled, in that case, we fill only updatePath */
	if (stat(updatePath, &fileAccess) == -1) {
		*result = construct_root_storage_file();
		if (*result != CERTSVC_SUCCESS) {
			LOGE("Failed to create new store-root file, [result=%d]", *result);
			return CERTSVC_IO_ERROR;
		}
	}

	if (*keyfile == NULL) {
		*keyfile = keyfile_load(updatePath);
		if (*keyfile == NULL) {
			LOGE("Failed to create the store file, [%s]",updatePath);
			*result = CERTSVC_IO_ERROR;
		}
		LOGD("Keyfile loaded successfully, [%s].", updatePath);
	}

	if (*result!=CERTSVC_SUCCESS)
		return NULL;
	else
		return updatePath;
}

int get_common_name(char* path, X509* x509Struct, char** commonName) {

	int result = CERTSVC_SUCCESS;
	unsigned char* _commonName = NULL;
	CERT_CONTEXT* context = NULL;
	int commonNameLen = 0;
	unsigned char* tmpSubjectStr = NULL;
	const unsigned char* data = NULL;
	cert_svc_name_fld_data* certFieldData = NULL;

	if ((path == NULL) && (x509Struct == NULL)) {
		LOGE("Invalid input parameter.");
		return  CERTSVC_WRONG_ARGUMENT;
	}

	/* If x509Struct is empty, we need to read the certificate and construct the x509 structure */
	if (x509Struct == NULL) {
		if (path == NULL) {
			LOGE("Invalid input parameter.");
			return CERTSVC_WRONG_ARGUMENT;
		}

		context = cert_svc_cert_context_init();
		if (context == NULL) {
			LOGE("Failed to allocate memory.");
			return CERTSVC_BAD_ALLOC;
		}

		result = cert_svc_load_file_to_context(context, path);
		if (result != CERT_SVC_ERR_NO_ERROR) {
			LOGE("Failed to load file into context.");
			result = CERTSVC_FAIL;
			goto err;
		}

		if ((context->certBuf == NULL) || (context->certBuf->data == NULL)) {
			LOGE("Empty certificate buffer.");
			result = CERTSVC_FAIL;
			goto err;
		}

		data = context->certBuf->data;
		d2i_X509(&x509Struct, &data, context->certBuf->size); // only work for der content

		if (x509Struct == NULL) {
			LOGE("[ERR][%s] Fail to construct X509 structure.", __func__);
			result = CERT_SVC_ERR_INVALID_CERTIFICATE;
			goto err;
		}
	}

	/* At this point we assume that we have the x509Struct filled with information */
	if ((tmpSubjectStr = (unsigned char*) X509_NAME_oneline((x509Struct->cert_info->subject), NULL, 0)) == NULL) {
		LOGE("[ERR][%s] Fail to parse certificate.", __func__);
		result = CERTSVC_FAIL;
		goto err;
	}

	certFieldData = (cert_svc_name_fld_data*)malloc(sizeof(cert_svc_name_fld_data));
	if (certFieldData != NULL) {
		certFieldData->commonName = NULL;
		certFieldData->organizationName = NULL;
		certFieldData->organizationUnitName = NULL;
		certFieldData->emailAddress = NULL;
	}
	else {
		LOGE("Failed to allocate memory.");
		result = CERTSVC_BAD_ALLOC;
		goto err;
	}

	if ((result = cert_svc_util_parse_name_fld_data(tmpSubjectStr, certFieldData)) != CERT_SVC_ERR_NO_ERROR) {
		LOGE("[ERR][%s] Fail to parse cert_svc_name_fld_data.", __func__);
		result = CERTSVC_FAIL;
		goto err;
	}

	result = CERTSVC_SUCCESS;

	if (certFieldData->commonName != NULL) {
		commonNameLen = strlen((const char*)(certFieldData->commonName));
		_commonName = (unsigned char*)malloc(sizeof(unsigned char) * (commonNameLen + 1));
		if (_commonName == NULL) {
			LOGE("Failed to allocate memory.");
			result = CERTSVC_BAD_ALLOC;
			goto err;
		}
		memset(_commonName, 0x00, commonNameLen+1);
		memcpy(_commonName, certFieldData->commonName, commonNameLen);
	}
	else if (certFieldData->organizationName != NULL) {
		commonNameLen = strlen((const char*)(certFieldData->organizationName));
		_commonName = (unsigned char*)malloc(sizeof(unsigned char) * (commonNameLen + 1));
		if (_commonName == NULL) {
			LOGE("Failed to allocate memory.");
			result = CERTSVC_BAD_ALLOC;
			goto err;
		}
		memset(_commonName, 0x00, commonNameLen+1);
		memcpy(_commonName, certFieldData->organizationName, commonNameLen);
	}
	else if (certFieldData->organizationUnitName != NULL) {
		commonNameLen = strlen((const char*)(certFieldData->organizationUnitName));
		_commonName = (unsigned char*)malloc(sizeof(unsigned char) * (commonNameLen + 1));
		if (_commonName == NULL) {
			LOGE("Failed to allocate memory.");
			result = CERTSVC_BAD_ALLOC;
			goto err;
		}
		memset(_commonName, 0x00, commonNameLen+1);
		memcpy(_commonName, certFieldData->organizationUnitName, commonNameLen);
	}
	else if (certFieldData->emailAddress != NULL) {
		commonNameLen = strlen((const char*)(certFieldData->emailAddress));
		_commonName = (unsigned char*)malloc(sizeof(unsigned char) * (commonNameLen + 1));
		if (_commonName == NULL) {
			LOGE("Failed to allocate memory.");
			result = CERTSVC_BAD_ALLOC;
			goto err;
		}
		memset(_commonName, 0x00, commonNameLen+1);
		memcpy(_commonName, certFieldData->emailAddress, commonNameLen);
	}
	else {
		LOGE("Failed to get common name.");
		result = CERTSVC_FAIL;
		goto err;
	}

	*commonName = _commonName;
	LOGD("Success to get common name for title.");

err:
	if (x509Struct != NULL) { X509_free(x509Struct); }
	if (context != NULL) { cert_svc_cert_context_final(context); }
	if (certFieldData != NULL) {
		if (certFieldData->countryName != NULL) free(certFieldData->countryName);
		if (certFieldData->localityName != NULL) free(certFieldData->localityName);
		if (certFieldData->stateOrProvinceName != NULL) free(certFieldData->stateOrProvinceName);
		if (certFieldData->organizationName != NULL) free(certFieldData->organizationName);
		if (certFieldData->organizationUnitName != NULL) free(certFieldData->organizationUnitName);
		if (certFieldData->commonName != NULL) free(certFieldData->commonName);
		if (certFieldData->emailAddress != NULL) free(certFieldData->emailAddress);
		if (certFieldData != NULL) free(certFieldData);
	}
	if (tmpSubjectStr != 0) { OPENSSL_free(tmpSubjectStr); }

	return result;
}

int construct_root_storage_file() {

	int result = CERTSVC_SUCCESS;
	GKeyFile *keyfile = NULL;
	DIR *dir = NULL;
	gchar *data = NULL;
	gsize length;
	char *path = NULL;
	char *commonName = NULL;
	struct dirent *dp = NULL;
	struct dirent *pEntry = NULL;
	size_t len = offsetof(struct dirent, d_name)
		+ pathconf(CERTSVC_STORAGE_ROOT_DIR, _PC_NAME_MAX) + 1;
	int ret = 0;

	keyfile = keyfile_load(CERTSVC_STORAGE_SYSTEM_PATH);
	if(keyfile == NULL) {
		LOGE("Failed to create keyfile.");
		return CERTSVC_IO_ERROR;
	}

	dir = opendir(CERTSVC_STORAGE_ROOT_DIR);
	if (dir == NULL) {
		LOGE("Fail to access directory, [%s].", CERTSVC_STORAGE_ROOT_DIR);
		return CERTSVC_IO_ERROR;
	}

	pEntry = (struct dirent *)malloc(len);
	if (pEntry == NULL) {
		LOGE("Failed to alloc memory");
		return CERTSVC_BAD_ALLOC
	}

	while ((ret = readdir_r(dir, pEntry, &dp)) == 0 && dp) {
		if (strncmp(dp->d_name, "..", 2) == 0
			|| strncmp(dp->d_name, ".", 1) == 0
			|| (dp->d_type == DT_DIR))
			continue;

		/*dp->d_name has cert file name , tmp has complete cert file path*/
		path = get_complete_path(CERTSVC_STORAGE_ROOT_DIR, dp->d_name);
		if (path == NULL)
			goto freeTmp;

		result = get_common_name(path, NULL, &commonName);
		if (result != CERTSVC_SUCCESS)
			goto freeTmp;

		if ((dp->d_name != NULL) && (path != NULL) && (commonName != NULL)) {
			g_key_file_set_string(
				keyfile,
				(const gchar *)dp->d_name,
				CERTSVC_STORAGE_KEY_ALIAS,
				(const gchar *)commonName);

			g_key_file_set_string(
				keyfile,
				(const gchar *)dp->d_name,
				CERTSVC_STORAGE_KEY_PATH,
				(const gchar *)path);
		}

freeTmp:
		if (path != NULL) { free(path); path=NULL; }
		if (commonName != NULL) {
			free(commonName);
			commonName=NULL;
		}
	}

	data = g_key_file_to_data(keyfile, &length, NULL);
	if(data == NULL) {
		LOGE("Failed to write data in store file.");
		result = CERTSVC_BAD_ALLOC;
		goto free_keyfile;
	}

	if(!g_file_set_contents(CERTSVC_STORAGE_SYSTEM_PATH, data, length, NULL)) {
		LOGE("Failed to write data in store file.");
		result = CERTSVC_IO_ERROR;
		goto free_data;
	}

free_data:
	g_free(data);
free_keyfile:
	g_key_file_free(keyfile);
	if (dir != NULL)
		closedir(dir);

	free(pEntry);

	return result;
}

int  c_certsvc_free_root_certificate_list(CertSvcStoreCertList** certList) {

	int result = CERTSVC_SUCCESS;
	CertSvcStoreCertList* tmpNode = NULL;

	if (*certList==NULL) {
		LOGE("Certificate list argument is NULL.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	while(*certList!=NULL) {
		tmpNode = *certList;
		if(tmpNode->title != NULL) { free(tmpNode->title); }
		if(tmpNode->gname != NULL) { free(tmpNode->gname); }
		if(tmpNode->path != NULL)  { free(tmpNode->path);  }
		(*certList) = (*certList)->next;
		free(tmpNode);
	}
	certList = NULL;
	return result;
}

int  c_certsvc_get_root_certificate_list(CertSvcStoreCertList** certList, int* length) {

	int result = CERTSVC_SUCCESS;
	GKeyFile* keyFile = NULL;
	CertSvcStoreCertList* rootCertHead = NULL;
	CertSvcStoreCertList* tmpNode = NULL;
	CertSvcStoreCertList* currentNode = NULL;
	CertSvcStoreCertList* tmpFreeNode = NULL;

	if (*certList!=NULL) {
		LOGE("Certificate list argument is not NULL.");
		return CERTSVC_WRONG_ARGUMENT;
	}


	load_keyfile(&keyFile, &result);
	if ((result!=CERTSVC_SUCCESS) && (keyFile==NULL)) {
		LOGE("Failed to load store file.");
		result = CERTSVC_IO_ERROR;
	}

	/*Load the content of keyfile into rootCertList*/
	gchar** groups = NULL;
	gchar* alias = NULL;
	gchar* path = NULL;
	gint i = 0;

	/* Get the groups and iterate on it */
	groups = g_key_file_get_groups(keyFile, length);
	if(groups != NULL) {

		for (i=0; i<*length; i++)
		{
			alias = g_key_file_get_string(keyFile, groups[i], CERTSVC_STORAGE_KEY_ALIAS, NULL);
			path = g_key_file_get_string(keyFile , groups[i], CERTSVC_STORAGE_KEY_PATH, NULL);

			tmpNode = (CertSvcStoreCertList*) malloc (sizeof(CertSvcStoreCertList));
			if (tmpNode == NULL) {
				while (rootCertHead != NULL)
				{
					tmpFreeNode = rootCertHead;
					rootCertHead = rootCertHead->next;
					free(tmpFreeNode);
				}
				LOGE("Failed to allocate memory.");
				result = CERTSVC_BAD_ALLOC;
				goto freeKeyFile;
			}
			else {
				tmpNode->next = NULL;
				int tmplen = strlen((const char*)groups[i]);
				tmpNode->gname = (char*) malloc (sizeof(char) * (tmplen + 1));
				memset(tmpNode->gname, 0x00, tmplen+1);
				memcpy(tmpNode->gname, groups[i], tmplen);

				tmplen = strlen((const char*)alias);
				tmpNode->title = (char*) malloc (sizeof(char) * (tmplen + 1));
				memset(tmpNode->title, 0x00, tmplen+1);
				memcpy(tmpNode->title, alias, tmplen);

				tmplen = strlen((const char*)path);
				tmpNode->path = (char*) malloc (sizeof(char) * (tmplen + 1));
				memset(tmpNode->path, 0x00, tmplen+1);
				memcpy(tmpNode->path, path, tmplen);
			}

			if (i == 0) {
				rootCertHead = tmpNode;
				currentNode = rootCertHead;
				tmpNode = NULL;
			}
			else {
				currentNode->next = tmpNode;
				currentNode = tmpNode;
				tmpNode = NULL;
			}
			alias = NULL;
			path = NULL;
		}
		g_strfreev(groups);
	}
	else
		LOGE("No entries found in storage-file.");

	if (*certList==NULL)
		*certList = rootCertHead;

	LOGD("Success to create certificate list.");

freeKeyFile:
	g_key_file_free(keyFile);

	return result;
}
#endif
