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
#define _GNU_SOURCE
#define  _CERT_SVC_VERIFY_PKCS12

#include "pkcs12.h"
#include <cert-svc/cerror.h>
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
#include <ss_manager.h>
#include <dlfcn.h>
#include <cert-service-debug.h>

#define SYSCALL(call) while(((call) == -1) && (errno == EINTR))

#define CERTSVC_PKCS12_STORAGE_DIR  "/opt/share/cert-svc/pkcs12"
#define CERTSVC_PKCS12_STORAGE_FILE "storage"
#define CERTSVC_PKCS12_STORAGE_PATH CERTSVC_PKCS12_STORAGE_DIR "/" CERTSVC_PKCS12_STORAGE_FILE

static const char  CERTSVC_PKCS12_STORAGE_KEY_PKEY[]  = "pkey";
static const char  CERTSVC_PKCS12_STORAGE_KEY_CERTS[] = "certs";
static const gchar CERTSVC_PKCS12_STORAGE_SEPARATOR  = ';';
static const char  CERTSVC_PKCS12_UNIX_GROUP[] = "secure-storage::pkcs12";

static gboolean keyfile_check(const char *pathname) {
  int result;
  if(access(pathname, F_OK | R_OK | W_OK) == 0)
    return TRUE;
  SYSCALL(result = creat(pathname, S_IRUSR | S_IWUSR));
  if (result != -1) {
      close(result);
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
  ssm_file_info_t sfi;
  gboolean exists;

  trial = 0U;
 try_again:
  ++trial;
  result = generate_random_filepath(filepath);
  if(result != CERTSVC_SUCCESS)
    return result;
  if(with_secure_storage)
    exists = (access(*filepath, F_OK) == 0 || ssm_getinfo(*filepath, &sfi, SSM_FLAG_DATA, CERTSVC_PKCS12_UNIX_GROUP) == 0);
  else
    exists = (access(*filepath, F_OK) == 0);
  if(exists) {
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
  int result;
  struct stat st;
  int wr_res;
  GKeyFile *keyfile;
  gchar *bare;
  gchar *pkvalue;
  gchar **cvaluev;
  gsize i, n;
  gchar *data;
  gsize length;
  static int  initFlag = 0;
  const char appInfo[]  = "certsvcp12";

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
		result = CERTSVC_FAIL;
		goto free_keyfile;
	}

#define _CERT_SVC_VERIFY_PKCS12
#ifdef _CERT_SVC_VERIFY_PKCS12

	if (certv == NULL)
	{
		char* pSubject = NULL;
		char* pIssuerName = NULL;
		int isSelfSigned = 0;

		pSubject = X509_NAME_oneline(cert->cert_info->subject, NULL, 0);
		if (!pSubject)
		{
			LOGD("Failed to get subject name");
			result = CERTSVC_FAIL;
			goto free_keyfile;
		}

		pIssuerName = X509_NAME_oneline(cert->cert_info->issuer, NULL, 0);
		if (!pIssuerName)
		{
			LOGD("Failed to get issuer name");
			free(pSubject);
			result = CERTSVC_FAIL;
			goto free_keyfile;
		}

		if (strcmp((const char*)pSubject, (const char*)pIssuerName) == 0)
		{
			//self signed..
			isSelfSigned = 1;

			EVP_PKEY* pKey = X509_get_pubkey(cert);
			if (!pKey)
			{
				LOGD("Failed to get public key");
				result = CERTSVC_FAIL;
				free(pSubject);
				free(pIssuerName);
				goto free_keyfile;
			}

			if (X509_verify(cert, pKey) <= 0)
			{
				LOGD("P12 verification failed");
				result = CERTSVC_FAIL;
				EVP_PKEY_free(pKey);
				free(pSubject);
				free(pIssuerName);
				goto free_keyfile;
			}
			LOGD("P12 verification Success");
			EVP_PKEY_free(pKey);
		}
		else
		{
			isSelfSigned = 0;
			int res = 0;
			X509_STORE_CTX *cert_ctx = NULL;
			X509_STORE *cert_store = NULL;

			cert_store = X509_STORE_new();
			if (!cert_store)
			{
				LOGD("Memory allocation failed");
				free(pSubject);
				free(pIssuerName);
				result = CERTSVC_FAIL;
				goto free_keyfile;
			}

			res = X509_STORE_load_locations(cert_store, NULL, "/opt/etc/ssl/certs/");
			if (res != 1)
			{
				LOGD("P12 load certificate store failed");
				free(pSubject);
				free(pIssuerName);
				X509_STORE_free(cert_store);
				result = CERTSVC_FAIL;
				goto free_keyfile;
			}

			res = X509_STORE_set_default_paths(cert_store);
			if (res != 1)
			{
				LOGD("P12 load certificate store path failed");
				free(pSubject);
				free(pIssuerName);
				X509_STORE_free(cert_store);
				result = CERTSVC_FAIL;
				goto free_keyfile;
			}

			// initialize store and store context
			cert_ctx = X509_STORE_CTX_new();
			if (cert_ctx == NULL)
			{
				LOGD("Memory allocation failed");
				free(pSubject);
				free(pIssuerName);
				X509_STORE_free(cert_store);
				result = CERTSVC_FAIL;
				goto free_keyfile;
			}

			// construct store context
			if (!X509_STORE_CTX_init(cert_ctx, cert_store, cert, NULL))
			{
				LOGD("Memory allocation failed");
				free(pSubject);
				free(pIssuerName);
				X509_STORE_free(cert_store);
				X509_STORE_CTX_free(cert_ctx);
				result = CERTSVC_FAIL;
				goto free_keyfile;
			}

			res = X509_verify_cert(cert_ctx);
			if (res != 1)
			{
				LOGD("P12 verification failed");
				free(pSubject);
				free(pIssuerName);
				X509_STORE_free(cert_store);
				X509_STORE_CTX_free(cert_ctx);
				result = CERTSVC_FAIL;
				goto free_keyfile;
			}
			X509_STORE_free(cert_store);
			X509_STORE_CTX_free(cert_ctx);
			LOGD("P12 verification Success");
		}
		free(pSubject);
		free(pIssuerName);
	}
	else if (certv != NULL)
	{
		// Cert Chain
		int res = 0;
		X509_STORE_CTX *cert_ctx = NULL;
		X509_STORE *cert_store = NULL;

		cert_store = X509_STORE_new();
		if (!cert_store)
		{
			LOGD("Memory allocation failed");
			result = CERTSVC_FAIL;
			goto free_keyfile;
		}

		res = X509_STORE_load_locations(cert_store, NULL, "/opt/share/cert-svc/certs/ssl/");
		if (res != 1)
		{
			LOGD("P12 load certificate store failed");
			result = CERTSVC_FAIL;
			X509_STORE_free(cert_store);
			goto free_keyfile;
		}

		res = X509_STORE_set_default_paths(cert_store);
		if (res != 1)
		{
			LOGD("P12 load certificate path failed");
			result = CERTSVC_FAIL;
			X509_STORE_free(cert_store);
			goto free_keyfile;
		}

		// initialize store and store context
		cert_ctx = X509_STORE_CTX_new();
		if (cert_ctx == NULL)
		{
			LOGD("Memory allocation failed");
			result = CERTSVC_FAIL;
			X509_STORE_free(cert_store);
			goto free_keyfile;
		}

		// construct store context
		if (!X509_STORE_CTX_init(cert_ctx, cert_store, cert, NULL))
		{
			LOGD("Memory allocation failed");
			result = CERTSVC_FAIL;
			X509_STORE_free(cert_store);
			X509_STORE_CTX_free(cert_ctx);
			goto free_keyfile;
		}

		X509_STORE_CTX_trusted_stack(cert_ctx, certv);

		res = X509_verify_cert(cert_ctx);
		if (res != 1)
		{
			LOGD("P12 verification failed");
			result = CERTSVC_FAIL;
			X509_STORE_free(cert_store);
			X509_STORE_CTX_free(cert_ctx);
			goto free_keyfile;
		}

		LOGD("P12 verification Success");
		X509_STORE_free(cert_store);
		X509_STORE_CTX_free(cert_ctx);
	}
#endif //_CERT_SVC_VERIFY_PKCS12
  nicerts = certv ? sk_X509_num(certv) : 0;
  cvaluev = (gchar **)calloc(1 + nicerts, sizeof(gchar *));
  n = 0;

  result = unique_filename(&unique, TRUE);
  if(result != CERTSVC_SUCCESS)
    goto clean_cert_chain_and_pkey;
  if((stream = fopen(unique, "w")) == NULL) {
    free(unique);
    result = CERTSVC_IO_ERROR;
    goto clean_cert_chain_and_pkey;
  }
  result = PEM_write_PrivateKey(stream, key, NULL, NULL, 0, NULL, NULL);
  fclose(stream);
  if(result == 0) {
    result = CERTSVC_FAIL;
    goto clean_cert_chain_and_pkey;
  }
  wr_res = ssm_write_file(unique, SSM_FLAG_DATA, CERTSVC_PKCS12_UNIX_GROUP);
  if(wr_res != 0) {
    free(unique);
    result = CERTSVC_FAIL;
    goto clean_cert_chain_and_pkey;
  }
  bare = bare_filename(unique);
  if(bare) {
    pkvalue = g_strdup(bare);
    g_key_file_set_string(keyfile, alias, CERTSVC_PKCS12_STORAGE_KEY_PKEY, pkvalue);
  }
  free(unique);
  result = unique_filename(&unique, FALSE);
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
  for(i = 0; i < nicerts; i++) {
    result = unique_filename(&unique, FALSE);
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

#if 1
  	SECURE_LOGD("( %s, %s)", path, password);
    void* pSymAddr = NULL;
	void* pInitAddr = NULL;
	typedef int (*InsertPkcs12FuncPointer)(const char*, const char*);
	typedef void (*InitAppInfoPointer)(const char*, const char*);

	InsertPkcs12FuncPointer pInsertPkcs12FuncPointer = NULL;
	InitAppInfoPointer pInit = NULL;

	void* dlHandle = dlopen("/usr/lib/osp/libosp-appfw.so", RTLD_LAZY);
	if (!dlHandle)
	{
		LOGD("Failed to open so with reason : %s",  dlerror());
		goto free_data;
	}

	pInsertPkcs12FuncPointer = (InsertPkcs12FuncPointer)dlsym(dlHandle, "InsertPkcs12Content");
	if (dlerror() != NULL)
	{
		LOGD("Failed to find InsertPkcs12Content symbol : %s",  dlerror());
		goto free_data;
	}

	if(initFlag == 0)
	{
		pInit = (InitAppInfoPointer)dlsym(dlHandle, "InitWebAppInfo");
		if (dlerror() != NULL)
		{
			LOGD("Failed to find InitWebAppInfo symbol : %s",  dlerror());
			goto free_data;
		}

		pInit(appInfo, NULL);
		initFlag = 1;
	}

	int errCode = pInsertPkcs12FuncPointer(path, password);
	if (errCode != 0)
	{
		LOGD("dlHandle is not able to call function");
		goto free_data;
	}
	dlclose(dlHandle);
#endif

 free_data:
  g_free(data);
  if(dlHandle){
    dlclose(dlHandle);
  }
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
  for(i = 0; i < *ncerts; i++)
      (*certs)[i] = g_strdup_printf("%s/%s", CERTSVC_PKCS12_STORAGE_DIR, barev[i]);
  (*certs)[*ncerts] = NULL;
  g_strfreev(barev);
free_keyfile:
  g_key_file_free(keyfile);
  return CERTSVC_SUCCESS;
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
  ssm_file_info_t sfi;
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
    else if(ssm_getinfo(spkp, &sfi, SSM_FLAG_DATA, CERTSVC_PKCS12_UNIX_GROUP) == 0) {
      if((*buffer = malloc(sfi.originSize))) {
        if(ssm_read(spkp, *buffer, sfi.originSize, count, SSM_FLAG_DATA, CERTSVC_PKCS12_UNIX_GROUP) != 0) {
          c_certsvc_pkcs12_private_key_free(*buffer);
          result = CERTSVC_FAIL;
        }
      }
      else
        result = CERTSVC_BAD_ALLOC;
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

int c_certsvc_pkcs12_delete(const gchar *alias) {
  gchar **certs;
  gsize ncerts;
  char *pkey;
  char *spkp;
  int result;
  GKeyFile *keyfile;
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
    unlink(certs[i]);
  if(pkey != NULL) {
      if(asprintf(&spkp, "%s/%s", CERTSVC_PKCS12_STORAGE_DIR, pkey) == -1) {
          result = CERTSVC_BAD_ALLOC;
          goto data_free;
      }
      ssm_delete_file(spkp, SSM_FLAG_DATA, CERTSVC_PKCS12_UNIX_GROUP);
      free(spkp);
  }
 data_free:
  g_free(data);
 keyfile_free:
  g_key_file_free(keyfile);
 keyfile_load_failed:
  if(ncerts != 0)
      c_certsvc_pkcs12_free_certificates(certs);
 load_certificates_failed:
  return result;
}
