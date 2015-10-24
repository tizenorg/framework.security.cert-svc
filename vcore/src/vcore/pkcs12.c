/**
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <db-util.h>

#include <ss_manager.h>

#include <cert-service.h>
#include <cert-service-util.h>
#include <cert-service-debug.h>
#include <cert-svc/cerror.h>
#include <cert-svc-client.h>

#include <pkcs12.h>

#define SYSCALL(call) while(((call) == -1) && (errno == EINTR))

#define START_CERT      "-----BEGIN CERTIFICATE-----"
#define END_CERT        "-----END CERTIFICATE-----"
#define START_TRUSTED   "-----BEGIN TRUSTED CERTIFICATE-----"
#define END_TRUSTED     "-----END TRUSTED CERTIFICATE-----"
#define START_KEY       "-----BEGIN PRIVATE KEY-----"
#define END_KEY         "-----END PRIVATE KEY-----"

#define CERTSVC_PKCS12_STORAGE_FILE  "storage"

#define CERTSVC_PKCS12_STORAGE_PATH CERTSVC_PKCS12_STORAGE_DIR "/" CERTSVC_PKCS12_STORAGE_FILE

#define MAX_BUFFER_SIZE 16;
#define _CERT_SVC_VERIFY_PKCS12

static const char  CERTSVC_PKCS12_STORAGE_KEY_PKEY[]    = "pkey";
static const char  CERTSVC_PKCS12_STORAGE_KEY_CERTS[]   = "certs";
static const gchar CERTSVC_PKCS12_STORAGE_SEPARATOR     = ';';
static const char  CERTSVC_PKCS12_UNIX_GROUP[]          = "secure-storage::pkcs12";

sqlite3 *cert_store_db = NULL;

static gboolean keyfile_check(const char *pathname) {
  int result;
  if(access(pathname, F_OK | R_OK | W_OK) == 0)
    return TRUE;
  SYSCALL(result = creat(pathname, S_IRUSR | S_IWUSR));
  if (result != -1) {
      result = close(result);
      if(result == -1)
        SLOGD("Failed to close, errno : %d",  errno);
      return TRUE;
  } else {
      return FALSE;
  }
}

static GKeyFile *keyfile_load(const char *pathname) {
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

static int generate_random_filepath(char **filepath) {
  int generator;
  int64_t random;
  SHA_CTX ctx;
  unsigned char d[SHA_DIGEST_LENGTH];
  int result;

  if(!filepath)
    return CERTSVC_WRONG_ARGUMENT;

  SYSCALL(generator = open("/dev/urandom", O_RDONLY));
  if(generator == -1)
    return CERTSVC_FAIL;
  SYSCALL(result = read(generator, &random, sizeof(random)));
  if(result == -1) {
    SYSCALL(close(generator));
    return CERTSVC_FAIL;
  }
  SYSCALL(result = close(generator));
  if(result == -1)
    return CERTSVC_FAIL;

  SHA1_Init(&ctx);
  SHA1_Update(&ctx, &random, sizeof(random));
  SHA1_Final(d, &ctx);

  result = asprintf(filepath, "%s/"                            \
                    "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x" \
                    "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                    CERTSVC_PKCS12_STORAGE_DIR,
                    d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9],
                    d[10], d[11], d[12], d[13], d[14], d[15], d[16], d[17], d[18], d[19]);
  return (result != -1) ? CERTSVC_SUCCESS : CERTSVC_BAD_ALLOC;
}

static int unique_filename(char **filepath, gboolean with_secure_storage) {
  const unsigned attempts = 0xFFU;
  unsigned trial;
  int result;
  gboolean exists;
  char* data = NULL;

  trial = 0U;
 try_again:
  ++trial;
  result = generate_random_filepath(filepath);
  if(result != CERTSVC_SUCCESS)
    return result;
  if(with_secure_storage)
    exists = (access(*filepath, F_OK) == 0 || ssa_get(*filepath, &data, CERTSVC_PKCS12_UNIX_GROUP, NULL) >= 0);
  else
    exists = (access(*filepath, F_OK) == 0);
  if(exists) {
	if(data){
        free(data);
        data = NULL;
    }
    free(*filepath);
    if(trial + 1 > attempts)
      return CERTSVC_FAIL;
    else
      goto try_again;
  }
  return CERTSVC_SUCCESS;
}

static char *bare_filename(char *filepath) {
  char *needle;
  if(!filepath)
    return NULL;
  needle = strrchr(filepath, '/');
  if(!needle)
    return NULL;
  return *(++needle) ? needle : NULL;
}

#ifdef TIZEN_FEATURE_CERT_SVC_STORE_CAPABILITY

char* get_complete_path(const char *str1, char *str2) {

	size_t str1_len = strlen(str1);
    char *result = NULL;
    int as_result = -1;

    if (str1[str1_len - 1] != '/')
        as_result = asprintf(&result, "%s/%s", str1, str2);
    else
        as_result = asprintf(&result, "%s%s", str1, str2);

    if (as_result >= 0)
        return result;
    else
        return NULL;
}

int read_from_file(const char *fileName, char **certBuffer, int *length) {

    int result = CERTSVC_SUCCESS;
    FILE *fp_out = NULL;
    int certLength = 0;
    struct stat st;

    if (stat(fileName, &st) == -1) {
        SLOGE("Certificate does not exist in disable folder.");
        result = CERTSVC_FAIL;
        goto err;
    }

    if (!(fp_out = fopen(fileName, "rb"))) {
        SLOGE("Fail to open file for reading, [%s].", fileName);
        result = CERTSVC_FAIL;
        goto err;
    }

    fseek(fp_out, 0L, SEEK_END);
    certLength = ftell(fp_out);
    if (certLength < 1) {
        SLOGE("Fail to get certificate length.");
        result = CERT_SVC_ERR_FILE_IO;
        goto err;
    }

    *certBuffer = (char*)malloc(sizeof(char) * ((int)certLength + 1));
    if (*certBuffer == NULL) {
        SLOGE("Fail to allocate memory");
        result = CERTSVC_BAD_ALLOC;
        goto err;
    }

    memset(*certBuffer, 0x00, certLength+1);
    rewind (fp_out);
    if (fread(*certBuffer, sizeof(char), (size_t)certLength, fp_out) != (size_t)certLength) {
        SLOGE("Fail to read file, [%s]", fileName);
        result = CERTSVC_IO_ERROR;
        goto err;
    }
    *length = certLength;

err:
    if (fp_out != NULL) {
        fclose(fp_out);
        fp_out = NULL;
    }
    return result;
}

int open_db(sqlite3 **db_handle, const char *db_path) {

    int result = -1;
    sqlite3 *handle;

    if (access(db_path, F_OK) == 0) {
        result = db_util_open(db_path, &handle, 0);
        if (result != SQLITE_OK) {
            SLOGE("connect to db [%s] failed!", db_path);
            return CERTSVC_FAIL;
        }
        *db_handle = handle;
        return CERTSVC_SUCCESS;
    }
    SLOGD("%s DB does not exists. Create one!!", db_path);

    result = db_util_open(db_path, &handle, 0);
    if (result != SQLITE_OK) {
        SLOGE("connect to db [%s] failed!", db_path);
        return CERTSVC_FAIL;
    }
    *db_handle = handle;
    return CERTSVC_SUCCESS;
}

int initialize_db() {

    int result = CERTSVC_SUCCESS;
    if (cert_store_db == NULL) {
        result = open_db(&cert_store_db, CERTSVC_SYSTEM_STORE_DB);
        if (result != CERTSVC_SUCCESS)
            SLOGE("Certsvc store DB creation failed");
    }
    return result;
}

int execute_select_query(char *query, sqlite3_stmt **stmt) {

    int result = CERTSVC_SUCCESS;
    sqlite3_stmt *stmts = NULL;

    if (cert_store_db != NULL) {
        sqlite3_close(cert_store_db);
        cert_store_db = NULL;
    }

    result = initialize_db();
    if (result != CERTSVC_SUCCESS) {
        SLOGE("Failed to initialise database.");
        result = CERTSVC_IO_ERROR;
        goto error;
    }

    result = sqlite3_prepare_v2(cert_store_db, query, strlen(query), &stmts, NULL);
    if (result != SQLITE_OK) {
        SLOGE("sqlite3_prepare_v2 failed [%s].", query);
        result = CERTSVC_FAIL;
        goto error;
    }

    *stmt = stmts;
    result = CERTSVC_SUCCESS;

error:
    return result;
}

int c_certsvc_pkcs12_set_certificate_status_to_store(CertStoreType storeType, int is_root_app, char* gname, CertStatus status) {

	return vcore_client_set_certificate_status_to_store(storeType, is_root_app, gname, status);
}

int c_certsvc_pkcs12_get_certificate_buffer_from_store(CertStoreType storeType, char* gname, char** certBuffer, size_t* certSize) {

    return vcore_client_get_certificate_from_store(storeType, gname, certBuffer, certSize, PEM_CRT);
}

int c_certsvc_pkcs12_get_certificate_status_from_store(CertStoreType storeType, const gchar *gname, int *status) {

    return vcore_client_get_certificate_status_from_store(storeType, gname, status);
}

int c_certsvc_pkcs12_alias_exists_in_store(CertStoreType storeType, const gchar *alias, gboolean *exists) {

    return vcore_client_check_alias_exist_in_store(storeType, alias, exists);
}

int c_certsvc_pkcs12_private_key_load_from_store(CertStoreType storeType, const gchar *gname, char **certBuffer, size_t *certSize) {

    return vcore_client_get_certificate_from_store(storeType, gname, certBuffer, certSize, (CertType)P12_PKEY);
}

int c_certsvc_pkcs12_delete_certificate_from_store(CertStoreType storeType, const char* gname) {

	int result = CERTSVC_SUCCESS;

	result = vcore_client_delete_certificate_from_store(storeType, gname);
	if(result == CERTSVC_SUCCESS)
		SLOG(LOG_INFO, "MDM_LOG_USER", "Object=certificate, AccessType=Uninstall, Result=Succeed");
	else
		SLOG(LOG_INFO, "MDM_LOG_USER", "Object=certificate, AccessType=Uninstall, Result=Failed");

	return result;
}

int c_certsvc_pkcs12_get_certificate_alias_from_store(CertStoreType storeType, const gchar *gname, char **alias) {

    return vcore_client_get_certificate_alias_from_store(storeType, gname, alias);
}

int c_certsvc_pkcs12_load_certificates_from_store(CertStoreType storeType, const gchar *gname, gchar ***certs, gsize *ncerts) {
    return vcore_client_load_certificates_from_store(storeType, gname, (char ***)certs, (int *)ncerts);
}

int get_common_name(const char* path, X509* x509Struct, char** commonName) {

    int result = CERTSVC_SUCCESS;
    int commonNameLen = 0;
    unsigned char* pCommonName = NULL;
    unsigned char* tmpSubjectStr = NULL;
    const unsigned char* data = NULL;
    CERT_CONTEXT* context = NULL;
    cert_svc_name_fld_data* certFieldData = NULL;

    if ((path == NULL) && (x509Struct == NULL)) {
        SLOGE("Invalid input parameter.");
        return  CERTSVC_WRONG_ARGUMENT;
    }

    /* If x509Struct is empty, we need to read the certificate and construct the x509 structure */
    if (x509Struct == NULL) {
        if (path == NULL) {
            SLOGE("Invalid input parameter.");
            return CERTSVC_WRONG_ARGUMENT;
        }

        context = cert_svc_cert_context_init();
        if (context == NULL) {
            SLOGE("Failed to allocate memory.");
            return CERTSVC_BAD_ALLOC;
        }

        result = cert_svc_load_file_to_context(context, path);
        if (result != CERT_SVC_ERR_NO_ERROR) {
            SLOGE("Failed to load file into context.");
            result = CERTSVC_FAIL;
            goto error;
        }

        if ((context->certBuf == NULL) || (context->certBuf->data == NULL)) {
            SLOGE("Empty certificate buffer.");
            result = CERTSVC_FAIL;
            goto error;
        }

        data = context->certBuf->data;
        d2i_X509(&x509Struct, &data, context->certBuf->size);

        if (x509Struct == NULL) {
            SLOGE("[ERR][%s] Fail to construct X509 structure.", __func__);
            result = CERT_SVC_ERR_INVALID_CERTIFICATE;
            goto error;
        }
    }

    if ((tmpSubjectStr = (unsigned char*) X509_NAME_oneline((x509Struct->cert_info->subject), NULL, 0)) == NULL) {
        SLOGE("[ERR][%s] Fail to parse certificate.", __func__);
        result = CERTSVC_FAIL;
        goto error;
    }

    certFieldData = (cert_svc_name_fld_data*)malloc(sizeof(cert_svc_name_fld_data));
    if (certFieldData != NULL) {
        certFieldData->commonName = NULL;
        certFieldData->organizationName = NULL;
        certFieldData->organizationUnitName = NULL;
        certFieldData->emailAddress = NULL;
    }
    else {
        SLOGE("Failed to allocate memory.");
        result = CERTSVC_BAD_ALLOC;
        goto error;
    }

    if ((result = cert_svc_util_parse_name_fld_data(tmpSubjectStr, certFieldData)) != CERT_SVC_ERR_NO_ERROR) {
        SLOGE("[ERR][%s] Fail to parse cert_svc_name_fld_data.", __func__);
        result = CERTSVC_FAIL;
        goto error;
    }

    result = CERTSVC_SUCCESS;
    if (certFieldData->commonName != NULL) {
        commonNameLen = strlen((const char*)(certFieldData->commonName));
        pCommonName = (unsigned char*)malloc(sizeof(unsigned char) * (commonNameLen + 1));
        if (pCommonName == NULL) {
            SLOGE("Failed to allocate memory.");
            result = CERTSVC_BAD_ALLOC;
            goto error;
        }
        memset(pCommonName, 0x00, commonNameLen+1);
        memcpy(pCommonName, certFieldData->commonName, commonNameLen);
    }
    else if (certFieldData->organizationName != NULL) {
        commonNameLen = strlen((const char*)(certFieldData->organizationName));
        pCommonName = (unsigned char*)malloc(sizeof(unsigned char) * (commonNameLen + 1));
        if (pCommonName == NULL) {
            SLOGE("Failed to allocate memory.");
            result = CERTSVC_BAD_ALLOC;
            goto error;
        }
        memset(pCommonName, 0x00, commonNameLen+1);
        memcpy(pCommonName, certFieldData->organizationName, commonNameLen);
    }
    else if (certFieldData->organizationUnitName != NULL) {
        commonNameLen = strlen((const char*)(certFieldData->organizationUnitName));
        pCommonName = (unsigned char*)malloc(sizeof(unsigned char) * (commonNameLen + 1));
        if (pCommonName == NULL) {
            SLOGE("Failed to allocate memory.");
            result = CERTSVC_BAD_ALLOC;
            goto error;
        }
        memset(pCommonName, 0x00, commonNameLen+1);
        memcpy(pCommonName, certFieldData->organizationUnitName, commonNameLen);
    }
    else if (certFieldData->emailAddress != NULL) {
        commonNameLen = strlen((const char*)(certFieldData->emailAddress));
        pCommonName = (unsigned char*)malloc(sizeof(unsigned char) * (commonNameLen + 1));
        if (pCommonName == NULL) {
            SLOGE("Failed to allocate memory.");
            result = CERTSVC_BAD_ALLOC;
            goto error;
        }
        memset(pCommonName, 0x00, commonNameLen+1);
        memcpy(pCommonName, certFieldData->emailAddress, commonNameLen);
    }
    else {
        SLOGE("Failed to get common name.");
        result = CERTSVC_FAIL;
        goto error;
    }

    *commonName = (char *)pCommonName;
    SLOGD("Success to get common name for title.");

error:
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

int  c_certsvc_pkcs12_free_aliases_loaded_from_store(CertSvcStoreCertList** certList) {
    int result = CERTSVC_SUCCESS;
    CertSvcStoreCertList* tmpNode = NULL;

    while (*certList!=NULL) {
        tmpNode = *certList;
        if(tmpNode->title != NULL) { free(tmpNode->title); }
        if(tmpNode->gname != NULL) { free(tmpNode->gname); }
        (*certList) = (*certList)->next;
        free(tmpNode);
    }

    if (cert_store_db != NULL) {
        sqlite3_close(cert_store_db);
        cert_store_db = NULL;
    }
    certList = NULL;
    return result;
}

int c_certsvc_pkcs12_get_root_certificate_list_from_store(CertStoreType storeType, CertSvcStoreCertList** certList, int* length) {
    return vcore_client_get_root_certificate_list_from_store(storeType, certList, length);
}

int c_certsvc_pkcs12_get_end_user_certificate_list_from_store(CertStoreType storeType, CertSvcStoreCertList** certList, int* length) {
    return vcore_client_get_end_user_certificate_list_from_store(storeType, certList, length);
}

int c_certsvc_pkcs12_get_certificate_list_from_store(CertStoreType storeType, int is_root_app, CertSvcStoreCertList** certList, int* length) {
    return vcore_client_get_certificate_list_from_store(storeType, is_root_app, certList, length);
}

int install_pem_file_format_to_store(CertStoreType storeType, const char* certBuffer, int certLength, \
		const gchar *alias, const char* path, char *private_key_gname, gchar *associated_gname, CertType decideCert) {

    int result = CERTSVC_SUCCESS;
    int readCount = 0;
    char* fileName = NULL;
    char* commonName = NULL;
    char *unique = NULL;
    BIO* pBio = NULL;
    X509* x509Struct = NULL;
    struct stat dirST;

    if (!certBuffer || !certLength) {
        SLOGE("Invalid argument. certBuffer is input cert.");
        return CERTSVC_WRONG_ARGUMENT;
    }

    if (decideCert == PEM_CRT) {
        result = unique_filename(&unique, FALSE);
        if (result != CERTSVC_SUCCESS) {
            SLOGE("Fail to generate unique filename.");
            return result;
        }
    }
    else
        unique = (char*)path;

    if (unique == NULL)	{
        SLOGE("Failed to get unique file name.");
        return result;
    }

    /* Get common name from buffer or from file */
    if (stat(path, &dirST) != -1) {
        result = get_common_name(path, NULL, &commonName);
        if (result != CERTSVC_SUCCESS) {
            pBio = BIO_new(BIO_s_mem());
            if (pBio == NULL) {
                SLOGE("Failed to allocate memory.");
                result = CERTSVC_BAD_ALLOC;
                goto error;
            }

            readCount = BIO_write(pBio, (const void*) certBuffer, certLength);
            if (readCount < 1) {
                SLOGE("Failed to load cert into bio.");
                result = CERTSVC_BAD_ALLOC;
                goto error;
            }

            x509Struct = PEM_read_bio_X509(pBio, NULL, 0, NULL);
            if (x509Struct == NULL) {
                SLOGE("Failed to create x509 structure.");
                result = CERTSVC_IO_ERROR;
                goto error;
            }

            result = get_common_name(NULL, x509Struct, &commonName);
            if (result != CERTSVC_SUCCESS) {
                SLOGE("CommonName is NULL");
                result = CERTSVC_FAIL;
                goto error;
            }
        }
    }

    /* storing the certificate to key-manager */
    fileName = bare_filename(unique);
    if ((decideCert == P12_END_USER) && (private_key_gname != NULL))
        result =  vcore_client_install_certificate_to_store(storeType, fileName, alias, private_key_gname, fileName, certBuffer, certLength, decideCert);
    else if ((decideCert == P12_TRUSTED) || (decideCert == P12_INTERMEDIATE))
        result =  vcore_client_install_certificate_to_store(storeType, fileName, commonName, NULL, associated_gname, certBuffer, certLength, decideCert);
    else
        result =  vcore_client_install_certificate_to_store(storeType, fileName, commonName, NULL, fileName, certBuffer, certLength, decideCert);

    if (result != CERTSVC_SUCCESS) {
        SLOGE("Failed to intall certificate.");
        result = CERTSVC_FAIL;
        goto error;
     }

    SLOGD("Success to add certificate in store.");

error:
    if (commonName)
        free(commonName);
    return result;
}

int install_crt_file(
        const char *path,
        CertStoreType storeType,
        const gchar *alias,
		char *private_key_gname,
        gchar *associated_gname,
        CertType decideCert)
{
    int result = CERTSVC_SUCCESS;
    int fileSize = 0;
    int certLength = 0;
    const char* header = NULL;
    const char* trailer = NULL;
    char* fileContent = NULL;
    const char* tmpBuffer = NULL;
    char* certBuffer = NULL;
    const char* tailEnd = NULL;

    if (read_from_file(path, &fileContent, &fileSize)!=CERTSVC_SUCCESS)
    {
    	SLOGE("Failed to read the file. [%s]",path);
        result = CERTSVC_IO_ERROR;
    	goto error;
    }

    tmpBuffer = fileContent;
    if (decideCert == PEM_CRT)
        header = strstr(tmpBuffer, START_CERT);
    else if (decideCert == P12_END_USER)
        header = strstr(tmpBuffer, START_CERT);
    else if ((decideCert == P12_TRUSTED)||(decideCert == P12_INTERMEDIATE))
        header = strstr(tmpBuffer, START_TRUSTED);
    else {
        SLOGE("Invalid cert.");
        result = CERTSVC_IO_ERROR;
        goto error;
    }

    if (header != NULL)	{
        /* Supports installation of only one certificate present in a CRT file */
        if (decideCert == PEM_CRT) {
            trailer = strstr(header, END_CERT);
            tailEnd = END_CERT;
        }
        else if (decideCert == P12_END_USER) {
            trailer = strstr(header, END_CERT);
            tailEnd = END_CERT;
        }
        else if ((decideCert == P12_TRUSTED)||(decideCert == P12_INTERMEDIATE)) {
            trailer = strstr(header, END_TRUSTED);
            tailEnd = END_TRUSTED;
        }
        else {
            SLOGE("Invalid certificate passed.");
            result = CERTSVC_IO_ERROR;
            goto error;
        }

        if (trailer != NULL) {
            tmpBuffer = trailer;
            certLength = ((int)(trailer - header) + strlen(tailEnd));
            certBuffer = (char*) malloc(sizeof(char) * (certLength+2));
            if (certBuffer == NULL) {
                result = CERTSVC_BAD_ALLOC;
                SLOGE("Fail to allocate memory.");
                goto error;
            }

            memset(certBuffer, 0x00, certLength+2);
            memcpy(certBuffer, header, certLength);
            certBuffer[certLength] = '\0';

            result = install_pem_file_format_to_store(storeType, certBuffer, certLength, alias, \
                                                      path, private_key_gname, associated_gname, decideCert);
            if (result != CERTSVC_SUCCESS) {
                result = CERTSVC_FAIL;
                SLOGE("Fail to install certificate.", path);
            }
        }
    }
    else {
        SLOGE("Invalid file type passed.");
        result = CERT_SVC_ERR_INVALID_CERTIFICATE;
    }

error:
    if (certBuffer)
        free(certBuffer);
    if (fileContent)
        free(fileContent);
    return result;
}

int handle_crt_pem_file_installation(CertStoreType storeType, const char *path, const gchar *alias) {

    int result = CERTSVC_SUCCESS;

    if ((strstr(path, ".crt")) != NULL || (strstr(path, ".pem")) != NULL) {
        SLOGD("certificate extention is .crt/.pem file");

        /* Installs CRT and PEM files. We will passing NULL for private_key_gname and associated_gname parameter in
         * install_crt_file(). Which means that there is no private key involved in the certificate which we are
         * installing and there are no other certificates related with the current certificate which is installed */
        result = install_crt_file(path, storeType, alias, NULL, NULL, PEM_CRT);
        if (result != CERTSVC_SUCCESS) {
            SLOGE("Failed to install the certificate.");
            result = CERTSVC_FAIL;
            goto error;
        }
    }
    else {
        SLOGE("Invalid certificate passed.");
        result = CERTSVC_FAIL;
        goto error;
    }
    SLOGD("Success to install the certificate.");

error:
    return result;
}

int verify_cert_details(X509** cert, STACK_OF(X509) **certv) {

    int result = CERTSVC_SUCCESS;
    char* pSubject = NULL;
    char* pIssuerName = NULL;
    X509_STORE_CTX *cert_ctx = NULL;
    X509_STORE *cert_store = NULL;
    int res = 0;

#ifdef _CERT_SVC_VERIFY_PKCS12
    if (*certv == NULL) {
        pSubject = X509_NAME_oneline((*cert)->cert_info->subject, NULL, 0);
        if (!pSubject) {
            SLOGE("Failed to get subject name");
            result = CERTSVC_FAIL;
            goto free_memory;
        }

        pIssuerName = X509_NAME_oneline((*cert)->cert_info->issuer, NULL, 0);
        if (!pIssuerName) {
            SLOGE("Failed to get issuer name");
            result = CERTSVC_FAIL;
            goto free_memory;
        }

        if (strcmp((const char*)pSubject, (const char*)pIssuerName) == 0) {
            /*self signed.. */
            EVP_PKEY* pKey = NULL;
            pKey = X509_get_pubkey(*cert);
            if (!pKey) {
                SLOGE("Failed to get public key");
                result = CERTSVC_FAIL;
                goto free_memory;
            }

            if (X509_verify(*cert, pKey) <= 0) {
                SLOGE("P12 verification failed");
                EVP_PKEY_free(pKey);
                result = CERTSVC_FAIL;
                goto free_memory;
            }
            SLOGD("P12 verification Success");
            EVP_PKEY_free(pKey);
        }
        else {
            cert_store = X509_STORE_new();
            if (!cert_store) {
                SLOGE("Memory allocation failed");
                result = CERTSVC_FAIL;
                goto free_memory;
            }

            res = X509_STORE_load_locations(cert_store, NULL, "/opt/etc/ssl/certs/");
            if (res != 1) {
                SLOGE("P12 load certificate store failed");
                X509_STORE_free(cert_store);
                result = CERTSVC_FAIL;
                goto free_memory;
            }

            res = X509_STORE_set_default_paths(cert_store);
            if (res != 1) {
                SLOGE("P12 load certificate store path failed");
                X509_STORE_free(cert_store);
                result = CERTSVC_FAIL;
                goto free_memory;
            }

            /* initialise store and store context */
            cert_ctx = X509_STORE_CTX_new();
            if (cert_ctx == NULL) {
                SLOGE("Memory allocation failed");
                result = CERTSVC_FAIL;
                goto free_memory;
            }

            /* construct store context */
            if (!X509_STORE_CTX_init(cert_ctx, cert_store, *cert, NULL)) {
                SLOGE("Memory allocation failed");
                result = CERTSVC_FAIL;
                goto free_memory;
            }

#ifdef P12_VERIFICATION_NEEDED
            res = X509_verify_cert(cert_ctx);
            if (res != 1) {
                SLOGE("P12 verification failed");
                result = CERTSVC_FAIL;
                goto free_memory;
            }
            SLOGD("P12 verification Success");
#endif
        }
    }
    else if (*certv != NULL) {
        /* Cert Chain */
        cert_store = X509_STORE_new();
        if (!cert_store) {
            SLOGE("Memory allocation failed");
            result = CERTSVC_FAIL;
            goto free_memory;
        }

        res = X509_STORE_load_locations(cert_store, NULL, CERT_SVC_STORE_PATH_DEFAULT);
        if (res != 1) {
            SLOGE("P12 load certificate store failed");
            result = CERTSVC_FAIL;
            goto free_memory;
        }

        res = X509_STORE_set_default_paths(cert_store);
        if (res != 1) {
            SLOGE("P12 load certificate path failed");
            result = CERTSVC_FAIL;
            goto free_memory;
        }

        /* initialise store and store context */
        cert_ctx = X509_STORE_CTX_new();
        if (cert_ctx == NULL) {
            SLOGE("Memory allocation failed");
            result = CERTSVC_FAIL;
            goto free_memory;
        }

        /* construct store context */
        if (!X509_STORE_CTX_init(cert_ctx, cert_store, *cert, NULL)) {
            SLOGE("Memory allocation failed");
            result = CERTSVC_FAIL;
            goto free_memory;
        }

        X509_STORE_CTX_trusted_stack(cert_ctx, *certv);
#ifdef P12_VERIFICATION_NEEDED
        res = X509_verify_cert(cert_ctx);
        if (res != 1) {
            SLOGE("P12 verification failed");
            result = CERTSVC_FAIL;
            goto free_memory;
        }
        SLOGD("P12 verification Success");
#endif
    }
#endif //_CERT_SVC_VERIFY_PKCS12

free_memory:
    if (pSubject != NULL) { free(pSubject); }
    if (pIssuerName != NULL) { free(pIssuerName); }
    if (cert_store != NULL) { X509_STORE_free(cert_store); }
    if (cert_ctx) { X509_STORE_CTX_free(cert_ctx); }
    return result;
}

int c_certsvc_pkcs12_import_from_file_to_store(CertStoreType storeTypes, const char *path, const char *password, const gchar *alias) {

    int	result = CERTSVC_SUCCESS;
    int readLen = 0;
    int tmpLen = 0;
    int nicerts = 0, i = 0, n = 0, ncerts = 0, wr_res;
    CertStoreType storeType = 0;
    FILE* stream = NULL;
    PKCS12* container = NULL;
    EVP_PKEY* key = NULL;
    X509* cert = NULL;
    STACK_OF(X509) *certv = NULL;
    gchar* bare = NULL;
    gchar* pkvalue = NULL;
    gchar** cvaluev = NULL;
    gchar **certs = NULL;
    char* tmpPkValue = NULL;
    char* unique = NULL;
    char fileBuffer[4096] = {0,};
    int loopCount = 0;
    CertType decideCert = INVALID_DATA;
    gboolean exists = FALSE;

    if ((!alias) || (strlen(alias) < 1) || (!path) || (strlen(path) < 1)) {
        SLOGE("Invalid input parameter.");
		SLOG(LOG_INFO, "MDM_LOG_USER", "Object=certificate, AccessType=Install, Result=Failed");
        return CERTSVC_WRONG_ARGUMENT;
    }

    while(1) {
        /* Iteration only possible from VPN_STORE till SYSTEM_STORE */
        if (loopCount == (MAX_STORE_ENUMS-1)) break;

        /* User should not install any form of certificates inside SYSTEM_STORE */
        if (((1 << loopCount) & storeTypes) == SYSTEM_STORE) {
            SLOGE("Not a valid store type installing certificate, store type passed [%d].", (1 << loopCount));
			SLOG(LOG_INFO, "MDM_LOG_USER", "Object=certificate, AccessType=Install, Result=Failed");
            return CERTSVC_INVALID_STORE_TYPE;
        }

        /* Iterating over all the stores */
        if ((1 << loopCount) & storeTypes) {
            storeType = 0;
            storeType = (CertStoreType) (1 << loopCount);
            SLOGD("Processing store type : [%s]", (storeType == VPN_STORE)? "VPN" : (storeType == WIFI_STORE)? "WIFI" : "EMAIL");

            /* check if the alias exists before installing certificate */
            result = c_certsvc_pkcs12_alias_exists_in_store(storeType, alias, &exists);
            if (result != CERTSVC_SUCCESS) {
                SLOGE("Failure to access database.");
                result = CERTSVC_FAIL;
                goto error;
            }

            if (exists!=CERTSVC_TRUE) {
                SLOGE("Alias exist in store [%s].", (storeType == VPN_STORE)? "VPN" : (storeType == WIFI_STORE)? "WIFI" : "EMAIL");
                result = CERTSVC_DUPLICATED_ALIAS;
                goto error;
            }

            /* Logic for handling crt/pem cert installation */
            /* Check if the input file is a PEM/CRT, since a PFX cert can also be opened without a password */
            if (password == NULL && ((strstr(path, ".pfx") == NULL) || (strstr(path, ".p12")))) {
                result = handle_crt_pem_file_installation(storeType, path, alias);
                if (result != CERTSVC_SUCCESS) {
                    SLOGE("Failed to install PEM/CRT file to store.");
                    result = CERTSVC_FAIL;
                }
                loopCount++;
                continue;
            }

            /* Logic for handling .pfx/.p12 cert installation */
            if ((stream = fopen(path, "rb")) == NULL) {
                SLOGE("Unable to open the file for reading [%s].", path);
                result = CERTSVC_IO_ERROR;
                goto error;
            }

            if (container == NULL) {
                container = d2i_PKCS12_fp(stream, NULL);
                fclose(stream);
                if (container == NULL) {
                    SLOGE("Failed to parse the input file passed.");
                    result = CERTSVC_FAIL;
                    goto error;
                }
            }

            /* To ensure when the code re-enters, we should clean up */
            if (key==NULL && cert==NULL && certv==NULL) {
                result = PKCS12_parse(container, password, &key, &cert, &certv);
                PKCS12_free(container);
                if (result == CERTSVC_FAIL) {
                    SLOGE("Failed to parse the file passed.");
                    result = CERTSVC_FAIL;
                    goto error;
                }

                result = verify_cert_details(&cert, &certv);
                if (result == CERTSVC_FAIL) {
                    SLOGE("Failed to verify p12 certificate.");
                    goto error;
                }
            }

            nicerts = 0;
            nicerts = certv ? sk_X509_num(certv) : 0;
            if (cvaluev != NULL) {
            for (i = 0; i < n; i++)
                 g_free(cvaluev[i]);
                 if (cvaluev) free(cvaluev);
                     cvaluev = NULL;
            }

            n = 0;
            cvaluev = (gchar **)calloc(1 + nicerts, sizeof(gchar *));
            if (unique != NULL) { free(unique); unique = NULL; }
            result = unique_filename(&unique, FALSE);
            if (result != CERTSVC_SUCCESS || !unique) {
                SLOGE("Unique filename generation failed.");
                goto error;
            }

            if ((stream = fopen(unique, "w+")) == NULL) {
                SLOGE("Unable to open the file for writing [%s].",unique);
                result = CERTSVC_IO_ERROR;
                goto error;
            }

            result = PEM_write_PrivateKey(stream, key, NULL, NULL, 0, NULL, NULL);
            if (result == 0) {
                SLOGE("Writing the private key contents failed.");
                result = CERTSVC_FAIL;
                fclose(stream);
                goto error;
            }

            fseek(stream, 0, SEEK_SET);
            memset(fileBuffer, 0, (sizeof(char)*4096));
            readLen=0;
            readLen = fread(fileBuffer, sizeof(char), 4096, stream);
            fclose(stream);
            if (readLen <= 0){
				SLOGE("Failed to read key file");
                result = CERTSVC_FAIL;
                goto error;
            }

            bare = bare_filename(unique);
            if (bare) {
                pkvalue = g_strdup(bare);
                tmpLen = strlen((const char*)pkvalue);
                tmpPkValue = (char*)malloc(sizeof(char) * (tmpLen + 1));
                memset(tmpPkValue, 0x00, tmpLen+1);
                memcpy(tmpPkValue, pkvalue, tmpLen);
            }

            decideCert = P12_PKEY;
            result = vcore_client_install_certificate_to_store(storeType, tmpPkValue, NULL, NULL, NULL, fileBuffer, readLen, decideCert);
            if (result != CERTSVC_SUCCESS) {
                SLOGD("Failed to store the private key contents.");
                result = CERTSVC_FAIL;
                goto error;
            }

            unlink(unique);
            if (unique!=NULL) { free(unique); unique=NULL; }
            result = unique_filename(&unique, FALSE);
            if (result != CERTSVC_SUCCESS || !unique) {
                SLOGE("Unique filename generation failed.");
                goto error;
            }

            if ((stream = fopen(unique, "w")) == NULL) {
                SLOGE("Unable to open the file for writing [%s].", unique);
                result = CERTSVC_IO_ERROR;
                goto error;
            }

            result = PEM_write_X509(stream, cert);
            fclose(stream);
            if (result == 0) {
                SLOGE("Failed to write contents to file.");
                result = CERTSVC_FAIL;
                goto error;
            }

            bare = bare_filename(unique);
            if (bare)
                cvaluev[n++] = g_strdup(bare);

            wr_res = -1;
            decideCert = P12_END_USER;
            wr_res = install_crt_file(unique, storeType, alias, tmpPkValue, NULL, decideCert);
            if (wr_res != CERTSVC_SUCCESS) {
                result = CERTSVC_FAIL;
                SLOGE("Failed to install the end user certificate.");
                goto error;
            }

            unlink(unique);
            for (i=nicerts; i>0; i--) {
                 result = unique_filename(&unique, FALSE);
                 if (result != CERTSVC_SUCCESS || !unique) {
                     SLOGE("Unique filename generation failed.");
                     goto error;
                 }

                 if ((stream = fopen(unique, "w")) == NULL) {
                      result = CERTSVC_IO_ERROR;
                      SLOGE("Unable to open the file for writing.");
                      goto error;
                 }

                 result = PEM_write_X509_AUX(stream, sk_X509_value(certv, i-1));
                 fclose(stream);
                 if (result == 0) {
                     result = CERTSVC_FAIL;
                     SLOGE("Unable to extract the certificates.");
                     goto error;
                 }

                 wr_res = -1;
                 if (i==nicerts)
                     decideCert = P12_INTERMEDIATE;
                 else
                     decideCert = P12_TRUSTED;
                 wr_res = install_crt_file(unique, storeType, alias, NULL, cvaluev[0], decideCert);
                 if (wr_res != CERTSVC_SUCCESS) {
                     result = CERTSVC_FAIL;
                     goto error;
                 }

                 unlink(unique);
                 bare = bare_filename(unique);
                 if (bare)
                     cvaluev[n++] = g_strdup(bare);
            }
        }
        loopCount++;
    }

error:
    /* if any certificate parsing/installation fails in middle,
     * the below logic will delete the chain installed in DB */
    if (result != CERTSVC_SUCCESS) {
		SLOG(LOG_INFO, "MDM_LOG_USER", "Object=certificate, AccessType=Install, Result=Failed");
        if (nicerts > 0) {
        	nicerts = 0; i = 0;
        	/* cvaluev[0] holds the end user certificate identifier which will be associated
        	 * to chain certs. Pull the cert chain based on end user cert and delete one by one. */
            if (c_certsvc_pkcs12_load_certificates_from_store(storeType, cvaluev[0], &certs, (gsize *)&ncerts) != CERTSVC_SUCCESS) {
                SLOGE("Unable to load certificates from store.");
                return result;
            }

            for (i=0; i<ncerts; i++) {
            	 if (certs[i] != NULL) {
    	             SLOGD("file to delete : %s",certs[i]);
                     c_certsvc_pkcs12_delete_certificate_from_store(storeType, (char *)certs[i]);
            	 }
            }

            if (certs[i] != NULL) {
                for (i=0; i<ncerts; i++)
                     g_free(certs[i]);
            }
        }
    }
	else
		SLOG(LOG_INFO, "MDM_LOG_USER", "Object=certificate, AccessType=Install, Result=Succeed");

    if (key != NULL) EVP_PKEY_free(key);
    if (cert != NULL) X509_free(cert);
    if (certv != NULL) sk_X509_free(certv);
    if (pkvalue != NULL) free(pkvalue);
    if (tmpPkValue != NULL) free(tmpPkValue);
    if (unique != NULL) free(unique);
    return result;
}

#endif


int c_certsvc_pkcs12_alias_exists(const gchar *alias, gboolean *exists) {
  GKeyFile *keyfile;

  if(exists == NULL)
    return CERTSVC_WRONG_ARGUMENT;
  keyfile = keyfile_load(CERTSVC_PKCS12_STORAGE_PATH);
  if(!keyfile)
    return CERTSVC_IO_ERROR;
  *exists = g_key_file_has_group(keyfile, alias);
  g_key_file_free(keyfile);
  return CERTSVC_SUCCESS;
}

int c_certsvc_pkcs12_import(const char *path, const char *password, const gchar *alias) {
  int exists;
  FILE *stream;
  PKCS12 *container;
  EVP_PKEY *key;
  X509 *cert;
  STACK_OF(X509) *certv;
  int nicerts;
  char *unique;
  int result = 0;
  struct stat st;
  int wr_res;
  GKeyFile *keyfile;
  gchar *bare;
  gchar *pkvalue;
  gchar **cvaluev;
  gsize i, n;
  gchar *data;
  gsize length;
  int readLen = 0;
  char fileBuffer[4096] = {0,};

  certv = NULL;
  pkvalue = NULL;
  if(!alias || strlen(alias) < 1)
    return CERTSVC_WRONG_ARGUMENT;
  result = c_certsvc_pkcs12_alias_exists(alias, &exists);
  if(result != CERTSVC_SUCCESS)
    return result;
  if(exists == TRUE)
    return CERTSVC_DUPLICATED_ALIAS;

  keyfile = keyfile_load(CERTSVC_PKCS12_STORAGE_PATH);
  if(!keyfile)
    return CERTSVC_IO_ERROR;
  if(stat(CERTSVC_PKCS12_STORAGE_PATH, &st) == -1) {
    if(mkdir(CERTSVC_PKCS12_STORAGE_PATH, S_IRWXU | S_IRWXG | S_IRWXO) == -1) {
      result = CERTSVC_FAIL;
      goto free_keyfile;
    }
  }

  if((stream = fopen(path, "rb")) == NULL) {
    result = CERTSVC_IO_ERROR;
    goto free_keyfile;
  }
  container = d2i_PKCS12_fp(stream, NULL);
  fclose(stream);
  if(container == NULL) {
    result = CERTSVC_FAIL;
    goto free_keyfile;
  }


  result = PKCS12_parse(container, password, &key, &cert, &certv);
  PKCS12_free(container);
	if (result == 0)
	{
		SLOGD("Failed to parse PKCS12");
		result = CERTSVC_FAIL;
		goto free_keyfile;
	}

	result = verify_cert_details(&cert, &certv);
	if (result == CERTSVC_FAIL)
	{
		SLOGE("Failed to parse the file passed.");
		goto free_keyfile;
	}

  nicerts = certv ? sk_X509_num(certv) : 0;
  cvaluev = (gchar **)calloc(1 + nicerts, sizeof(gchar *));
  n = 0;

  result = unique_filename(&unique, TRUE);
  if(result != CERTSVC_SUCCESS)
    goto clean_cert_chain_and_pkey;
  if((stream = fopen(unique, "w+")) == NULL) {
    free(unique);
    result = CERTSVC_IO_ERROR;
    goto clean_cert_chain_and_pkey;
  }
  result = PEM_write_PrivateKey(stream, key, NULL, NULL, 0, NULL, NULL);
  if(result == 0) {
    result = CERTSVC_FAIL;
    fclose(stream);
    free(unique);
    goto clean_cert_chain_and_pkey;
  }

  fseek(stream, 0, SEEK_SET);

  readLen = fread(fileBuffer, sizeof(char), 4096, stream);
  fclose(stream);
  if(readLen <= 0){
    free(unique);
    result = CERTSVC_FAIL;
    SLOGE("failed to read key file");
    goto clean_cert_chain_and_pkey;
  }

  wr_res = ssa_put(unique, fileBuffer, readLen, CERTSVC_PKCS12_UNIX_GROUP, NULL);
  if(wr_res <= 0) {
    free(unique);
    result = CERTSVC_FAIL;
    SLOGE("ssa_put failed : %d", wr_res);
    goto clean_cert_chain_and_pkey;
  }
  unlink(unique);

  bare = bare_filename(unique);
  if(bare) {
    pkvalue = g_strdup(bare);
    g_key_file_set_string(keyfile, alias, CERTSVC_PKCS12_STORAGE_KEY_PKEY, pkvalue);
  }
  free(unique);
  result = unique_filename(&unique, TRUE);
  if(result != CERTSVC_SUCCESS)
    goto clean_cert_chain_and_pkey;
  if((stream = fopen(unique, "w")) == NULL) {
    free(unique);
    result = CERTSVC_IO_ERROR;
    goto clean_cert_chain_and_pkey;
  }
  result = PEM_write_X509(stream, cert);
  fclose(stream);
  if(result == 0) {
    result = CERTSVC_FAIL;
    goto clean_cert_chain_and_pkey;
  }
  bare = bare_filename(unique);
  if(bare)
    cvaluev[n++] = g_strdup(bare);
  free(unique);
  for(i = 0; i < (unsigned int)nicerts; i++) {
    result = unique_filename(&unique, TRUE);
    if(result != CERTSVC_SUCCESS)
      goto clean_cert_chain_and_pkey;
    if((stream = fopen(unique, "w")) == NULL) {
      free(unique);
      result = CERTSVC_IO_ERROR;
      goto clean_cert_chain_and_pkey;
    }
    result = PEM_write_X509_AUX(stream, sk_X509_value(certv, i));
    fclose(stream);
    if(result == 0) {
      result = CERTSVC_FAIL;
      goto clean_cert_chain_and_pkey;
    }
    bare = bare_filename(unique);
    if(bare)
      cvaluev[n++] = g_strdup(bare);
    free(unique);
  }
  g_key_file_set_list_separator(keyfile, CERTSVC_PKCS12_STORAGE_SEPARATOR);
  g_key_file_set_string_list(keyfile, alias, CERTSVC_PKCS12_STORAGE_KEY_CERTS, (const gchar * const *)cvaluev, n);
  data = g_key_file_to_data(keyfile, &length, NULL);
  if(data == NULL) {
    result = CERTSVC_BAD_ALLOC;
    goto clean_cert_chain_and_pkey;
  }
  if(!g_file_set_contents(CERTSVC_PKCS12_STORAGE_PATH, data, length, NULL)) {
    result = CERTSVC_IO_ERROR;
    goto free_data;
  }
  result = CERTSVC_SUCCESS;

  SLOGD("( %s, %s)", path, password);

 free_data:
  g_free(data);

 clean_cert_chain_and_pkey:
  EVP_PKEY_free(key);
  X509_free(cert);
  sk_X509_free(certv);
  free(pkvalue);
 for(i = 0; i < n; i++) {
    g_free(cvaluev[i]);
 }
  free(cvaluev);
 free_keyfile:
  g_key_file_free(keyfile);
  return result;
}

int c_certsvc_pkcs12_aliases_load(gchar ***aliases, gsize *naliases) {
  GKeyFile *keyfile;

  keyfile = keyfile_load(CERTSVC_PKCS12_STORAGE_PATH);
  if(!keyfile)
    return CERTSVC_IO_ERROR;
  *aliases = g_key_file_get_groups(keyfile, naliases);
  g_key_file_free(keyfile);
  return CERTSVC_SUCCESS;
}

void c_certsvc_pkcs12_aliases_free(gchar **aliases) {
  g_strfreev(aliases);
}

int c_certsvc_pkcs12_has_password(const char *filepath, gboolean *passworded) {
  FILE *stream;
  EVP_PKEY *pkey;
  X509 *cert;
  PKCS12 *container;
  int result;

  if(passworded == NULL)
    return CERTSVC_WRONG_ARGUMENT;
  if((stream = fopen(filepath, "rb")) == NULL)
    return CERTSVC_IO_ERROR;
  container = d2i_PKCS12_fp(stream, NULL);
  fclose(stream);
  if(container == NULL)
    return CERTSVC_FAIL;
  result = PKCS12_parse(container, NULL, &pkey, &cert, NULL);
  PKCS12_free(container);
  if(result == 1) {
    EVP_PKEY_free(pkey);
    X509_free(cert);
    *passworded = FALSE;
    return CERTSVC_SUCCESS;
  }
  else {
    if(ERR_GET_REASON(ERR_peek_last_error()) == PKCS12_R_MAC_VERIFY_FAILURE) {
      *passworded = TRUE;
      return CERTSVC_SUCCESS;
    }
    else
      return CERTSVC_FAIL;
  }
}

int c_certsvc_pkcs12_load_certificates(const gchar *alias, gchar ***certs, gsize *ncerts) {
  GKeyFile *keyfile;
  gchar **barev;
  gsize i;
  int result = CERTSVC_SUCCESS;
  keyfile = keyfile_load(CERTSVC_PKCS12_STORAGE_PATH);
  if(!keyfile)
    return CERTSVC_IO_ERROR;
  g_key_file_set_list_separator(keyfile, CERTSVC_PKCS12_STORAGE_SEPARATOR);
  barev = g_key_file_get_string_list(keyfile, alias, CERTSVC_PKCS12_STORAGE_KEY_CERTS, ncerts, NULL);
  if(barev == NULL) {
      *ncerts = 0;
      goto free_keyfile;
  }
  *certs = g_malloc((*ncerts + 1) * sizeof(gchar *));
  if (!(*certs)) {
    result = CERTSVC_BAD_ALLOC;
    goto free_barev;
  }
  for(i = 0; i < *ncerts; i++)
      (*certs)[i] = g_strdup_printf("%s/%s", CERTSVC_PKCS12_STORAGE_DIR, barev[i]);
  (*certs)[*ncerts] = NULL;

free_barev:
  g_strfreev(barev);

free_keyfile:
  g_key_file_free(keyfile);
  return result;
}

void c_certsvc_pkcs12_free_certificates(gchar **certs) {
  gsize i = 0;
  if(certs == NULL)
    return;
  while(certs[i])
    g_free(certs[i++]);
  g_free(certs);
}

int c_certsvc_pkcs12_private_key_load(const gchar *alias, char **buffer, gsize *count) {
  GKeyFile *keyfile;
  gchar *pkey;
  GError *error;
  char *spkp;
  int result;

  if(!buffer)
    return CERTSVC_WRONG_ARGUMENT;
  keyfile = keyfile_load(CERTSVC_PKCS12_STORAGE_PATH);
  if(!keyfile)
    return CERTSVC_IO_ERROR;
  error = NULL;

  result = CERTSVC_SUCCESS;

  pkey = g_key_file_get_string(keyfile, alias, CERTSVC_PKCS12_STORAGE_KEY_PKEY, &error);
  if(error && error->code == G_KEY_FILE_ERROR_KEY_NOT_FOUND) {
    *count = 0;
    result = CERTSVC_SUCCESS;
  }
  else if(error)
    result = CERTSVC_FAIL;
  else {
    if(asprintf(&spkp, "%s/%s", CERTSVC_PKCS12_STORAGE_DIR, pkey) == -1) {
      spkp = NULL;
      result = CERTSVC_BAD_ALLOC;
    }
    else if((*count = ssa_get(spkp, buffer, CERTSVC_PKCS12_UNIX_GROUP, NULL)) <= 0) {
      result = CERTSVC_FAIL;
	  SLOGE("ssa_get failed : %s, %d", spkp, *count);
    }
    free(spkp);
    g_free(pkey);
  }
  g_key_file_free(keyfile);
  return result;
}

void c_certsvc_pkcs12_private_key_free(char *buffer) {
  free(buffer);
}

int certsvc_load_file_to_buffer(const char* filePath, unsigned char** certBuf, int* length)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	FILE* fp_in = NULL;
	unsigned long int fileSize = 0;

	/* get file size */
	if((ret = cert_svc_get_file_size(filePath, &fileSize)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to get file size, [%s]", __func__, filePath);
		return CERT_SVC_ERR_FILE_IO;
	}
	/* open file and write to buffer */
	if(!(fp_in = fopen(filePath, "rb"))) {
		SLOGE("[ERR][%s] Fail to open file, [%s]", __func__, filePath);
		return CERT_SVC_ERR_FILE_IO;
	}

	if(!(*certBuf = (unsigned char*)malloc(sizeof(unsigned char) * (unsigned int)(fileSize + 1)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(*certBuf, 0x00, (fileSize + 1));
	if(fread(*certBuf, sizeof(unsigned char), fileSize, fp_in) != fileSize) {
		SLOGE("[ERR][%s] Fail to read file, [%s]", __func__, filePath);
		ret = CERT_SVC_ERR_FILE_IO;
		goto err;
	}

	*length = fileSize;

err:
	if(fp_in != NULL)
		fclose(fp_in);
	return ret;
}

int c_certsvc_pkcs12_delete(const gchar *alias) {
  gchar **certs;
  gsize ncerts;
  char *pkey = NULL;
  char *spkp = NULL;
  int result, tmp;
  GKeyFile *keyfile = NULL;
  gchar *data;
  gsize i, length;

  data = NULL;
  result = c_certsvc_pkcs12_load_certificates(alias, &certs, &ncerts);
  if(result != CERTSVC_SUCCESS)
    goto load_certificates_failed;
  keyfile = keyfile_load(CERTSVC_PKCS12_STORAGE_PATH);
  if(!keyfile) {
    result = CERTSVC_IO_ERROR;
    goto keyfile_load_failed;
  }
  pkey = g_key_file_get_string(keyfile, alias, CERTSVC_PKCS12_STORAGE_KEY_PKEY, NULL);
  if(g_key_file_remove_group(keyfile, alias, NULL)) {
    data = g_key_file_to_data(keyfile, &length, NULL);
    if(data == NULL) {
      result = CERTSVC_BAD_ALLOC;
      goto keyfile_free;
    }
    if(!g_file_set_contents(CERTSVC_PKCS12_STORAGE_PATH, data, length, NULL)) {
      result = CERTSVC_IO_ERROR;
      goto data_free;
    }
  }

  for(i = 0; i < ncerts; i++)
  {
    unlink(certs[i]);
  }
  if(pkey != NULL) {
      if(asprintf(&spkp, "%s/%s", CERTSVC_PKCS12_STORAGE_DIR, pkey) == -1) {
          result = CERTSVC_BAD_ALLOC;
          goto data_free;
      }
      tmp = ssa_delete(spkp, CERTSVC_PKCS12_UNIX_GROUP);
      if (tmp < 0) {
		SLOGE("[ERR][%s] ssa_delete failed. ret[%d]", __func__, tmp);
      }
  }
 data_free:
  g_free(data);
 keyfile_free:
  g_key_file_free(keyfile);
  if(spkp != NULL)
      free(spkp);
 keyfile_load_failed:
  if(ncerts != 0)
      c_certsvc_pkcs12_free_certificates(certs);
 load_certificates_failed:
  return result;
}


int cert_svc_get_file_size(const char* filepath, unsigned long int* length)
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
