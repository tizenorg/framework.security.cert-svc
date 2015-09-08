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
 * @file        pkcs12.c
 * @author      Jacek Migacz (j.migacz@samsung.com)
 * @version     1.0
 * @brief       PKCS#12 container manipulation routines.
 */
#ifndef _PKCS12_H_
#define _PKCS12_H_

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

int  c_certsvc_pkcs12_alias_exists(const gchar *alias, gboolean *exists);
int  c_certsvc_pkcs12_import(const char *path, const char *password, const gchar *alias);
int  c_certsvc_pkcs12_aliases_load(gchar ***aliases, gsize *naliases);
void c_certsvc_pkcs12_aliases_free(gchar **aliases);
int  c_certsvc_pkcs12_has_password(const char *filepath, gboolean *passworded);
int  c_certsvc_pkcs12_load_certificates(const gchar *alias, gchar ***certificates, gsize *ncertificates);
void c_certsvc_pkcs12_free_certificates(gchar **certs);
int  c_certsvc_pkcs12_private_key_load(const gchar *alias, char **pkey, gsize *count);
void c_certsvc_pkcs12_private_key_free(char *buffer);
int  c_certsvc_pkcs12_delete(const gchar *alias);
//static void _delete_from_osp_cert_mgr(const char* path);
int certsvc_load_file_to_buffer(const char* filePath, unsigned char** certBuf, int* length);
int cert_svc_get_file_size(const char* filepath, unsigned long int* length);

#ifdef __cplusplus
}
#endif

#endif
