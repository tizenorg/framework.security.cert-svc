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
 * @file        cpkcs12.h
 * @author      Jacek Migacz (j.migacz@samsung.com)
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @brief       This is part of C api for PKCS#12/PFX storage routines.
 */
#ifndef _CERTSVC_CPKCS12_H_
#define _CERTSVC_CPKCS12_H_

#include <cert-svc/cinstance.h>
#include <cert-svc/cstring.h>
#include <cert-svc/ccert.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Query PKCS#12 storage to find out whenever new alias proposal is unique.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] proposal Desired alias name.
 * @param[out] is_unique CERTSVC_TRUE (if there isn't such alias already) or CERTSVC_FALSE.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_pkcs12_alias_exists(CertSvcInstance instance,
                                CertSvcString alias,
                                int *is_unique);

/**
 * Import PKCS#12 container from file.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] path Path to container file.
 * @param[in] password Container password (can be empty or NULL).
 * @param[in] alias Logical name for certificate bundle idenification (can't be empty).
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_INVALID_PASSWORD, CERTSVC_WRONG_ARGUMENT, CERTSVC_DUPLICATED_ALIAS
 */
int certsvc_pkcs12_import_from_file(CertSvcInstance instance,
                                    CertSvcString path,
                                    CertSvcString password,
                                    CertSvcString alias);

/**
 * Get a list of PKCS#12 bundles from storage. This list could be freed by:
 * certsvc_string_list_free, certsvc_instance_reset, certsvc_instance_free.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[out] pfxIdStringList List of PKCS#12 aliases.
 * @return CERTSVC_SUCCESS, CERTSVC_BAD_ALLOC, CERTSVC_FAIL
 */
int certsvc_pkcs12_get_id_list(CertSvcInstance instance,
                               CertSvcStringList *pfxIdStringList);

/**
 * Check whenever PKCS#12 container is password protected.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] path Path to container file.
 * @param[out] has_password CERTSVC_TRUE (if container is password protected) or CERTSVC_FALSE.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_pkcs12_has_password(CertSvcInstance instance,
                                CertSvcString filepath,
                                int *has_password);

/**
 * Get a list of certificates from PKCS#12 bundle. You may free this list by:
 * certsvc_certificate_list_free. You may free certificates from list with:
 * certsvc_certificate_free.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] pfxIdString Identification of pfx/pkcs file.
 * @param[out] certificateList List of certificates.
 * @return CERTSVC_SUCCESS, CERTSVC_BAD_ALLOC, CERTSVC_FAIL, CERTSVC_IO_ERROR
 */
int certsvc_pkcs12_load_certificate_list(CertSvcInstance instance,
                                         CertSvcString alias,
                                         CertSvcCertificateList* certificateList);

/**
 * This function will load to memory private file content. This functin will
 * not parse it in any way.
 * This memory must be freed by certsvc_private_key_free.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] prfIdString Container bundle identifier.
 * @param[out] buffer Poiner to newly-allocated memory with private key data.
 * @param[out] size Size of the newly-allocated buffer. Zero means there is no key.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_pkcs12_private_key_dup(CertSvcInstance instance,
                                   CertSvcString alias,
                                   char **buffer,
                                   size_t *size);

/**
 * Couter-routine for certsvc_pkcs12_private_key_dup.
 *
 * @param[in] pointer Memory claimed by private key.
 */
void certsvc_pkcs12_private_key_free(char *buffer);

/**
 * Remove logical PKCS#12 container with associated certificates and private key.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] alias Container bundle identifier.
 * @return CERTSVC_SUCCESS, CERTSVC_IO_ERROR, CERTSVC_BAD_ALLOC
 */
int certsvc_pkcs12_delete(CertSvcInstance instance,
                          CertSvcString alias);

#ifdef __cplusplus
}
#endif

#endif
