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
 * @param[in] alias Logical name for certificate bundle identification (can't be empty).
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

#ifdef TIZEN_FEATURE_CERT_SVC_STORE_CAPABILITY
/**
 * This function will load to memory private file content. This functin will
 * not parse it in any way.
 * This memory must be freed by certsvc_private_key_free.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] storeType Refers to VPN_STORE / WIFI_STORE / EMAIL_STORE / SYSTEM_STORE / ALL_STORE.
 * @param[in] gname Container bundle identifier.
 * @param[out] certBuffer Poiner to newly-allocated memory with private key data.
 * @param[out] certsize Size of the newly-allocated buffer. Zero means there is no key.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_pkcs12_private_key_dup_from_store(CertSvcInstance instance,
                                              CertStoreType storeType,
                                              CertSvcString gname,
                                              char **certBuffer,
                                              size_t *certsize);

/**
 * This function will set the status for the specified certificate in a particular
 * store to enabled / disabled.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] storeType Refers to VPN_STORE / WIFI_STORE / EMAIL_STORE / SYSTEM_STORE / ALL_STORE.
 * @param[in] is_root_app Set to ENABLED/DISABLED. Should be ENABLED if master application is changing the status, else DISABLED for other applications.
 * @param[in] gname Referred as group name, is the key for accessing the certificate.
 * @param[in] status Allows to set the status of the certificate to enabled / disabled.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT, CERTSVC_INVALID_STORE_TYPE
 */
int certsvc_pkcs12_set_certificate_status_to_store(CertSvcInstance instance,
                                            CertStoreType storeType,
                                            int is_root_app,
                                            CertSvcString gname,
                                            CertStatus status);

/**
 * This function will get the status for the specified certificate in a particular
 * store.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] storeType Refers to VPN_STORE / WIFI_STORE / EMAIL_STORE / SYSTEM_STORE / ALL_STORE.
 * @param[in] gname Referred as group name, is the key for accessing the certificate.
 * @param[out] status refers to weather the certificate is enabled/disabled.
 * @return Disable=0, Enable=1, Fail=-1
 */
int certsvc_pkcs12_get_certificate_status_from_store(CertSvcInstance instance,
                                              CertStoreType storeType,
                                              CertSvcString gname,
                                              int *status);

/**
 * This function will get the Alias name, Path to certificate, Certificate status of all
 * the certificates present in the specified certificate store.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] storeType Refers to VPN_STORE / WIFI_STORE / EMAIL_STORE / SYSTEM_STORE / ALL_STORE.
 * @param[out] certList Linked-list having all the information about each certificate present in a store.
 * @param[out] length Provides the length of the linked list.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT, CERTSVC_INVALID_STORE_TYPE
 */
int certsvc_pkcs12_get_certificate_list_from_store(CertSvcInstance instance,
                                            CertStoreType storeType,
                                            int is_root_app,
                                            CertSvcStoreCertList** certList,
                                            int* length);

/**
 * This function will get the Alias name, Path to certificate, Certificate status of all
 * the end user certificates present in the specified certificate store.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] storeType Refers to VPN_STORE / WIFI_STORE / EMAIL_STORE / SYSTEM_STORE / ALL_STORE.
 * @param[out] certList Linked-list having all the information about each certificate present in a store.
 * @param[out] length Provides the length of the linked list.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT, CERTSVC_INVALID_STORE_TYPE
 */
int certsvc_pkcs12_get_end_user_certificate_list_from_store(CertSvcInstance instance,
                                            CertStoreType storeType,
                                            CertSvcStoreCertList** certList,
                                            int* length);

/**
 * This function will get the Alias name, Path to certificate, Certificate status of all
 * the root/trusted certificates present in the specified certificate store.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] storeType Refers to VPN_STORE / WIFI_STORE / EMAIL_STORE / SYSTEM_STORE / ALL_STORE.
 * @param[out] certList Linked-list having all the information about each certificate present in a store.
 * @param[out] length Provides the length of the linked list.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT, CERTSVC_INVALID_STORE_TYPE
 */
int certsvc_pkcs12_get_root_certificate_list_from_store(CertSvcInstance instance,
                                            CertStoreType storeType,
                                            CertSvcStoreCertList** certList,
                                            int* length);

/**
 * This function will free all the linked list of data structure holding the information about
 * all the certificates present in a store which was previously by calling the
 * certsvc_get_certificate_list_from_store() function.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] certList The structure which need to be freed.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT, CERTSVC_INVALID_STORE_TYPE
 */
int certsvc_pkcs12_free_certificate_list_loaded_from_store(CertSvcInstance instance,
                                                    CertSvcStoreCertList** certList);

/**
 * This function will provide the certificate back for the gname provided.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] storeType Refers to VPN_STORE / WIFI_STORE / EMAIL_STORE / SYSTEM_STORE / ALL_STORE.
 * @param[in[ gname Referred as group name, is the key for accessing the certificate.
 * @param[out] certificate Certificate holding the information.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_BAD_ALLOC
 */
int certsvc_pkcs12_get_certificate_from_store(CertSvcInstance instance,
                                       CertStoreType storeType,
                                       char *gname,
                                       CertSvcCertificate *certificate);

/**
 * This function will give back the the encoded certificate buffer for the matching
 * alias present in the specified store.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] storeType Refers to VPN_STORE / WIFI_STORE / EMAIL_STORE / SYSTEM_STORE / ALL_STORE.
 * @param[in] gname Referred as group name, is the key for accessing the certificate.
 * @param[out] certBuffer Buffer containing the encoded certificate.
 * @param[out] certSize Size of the buffer.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT, CERTSVC_INVALID_STORE_TYPE
 */
int certsvc_pkcs12_get_certificate_info_from_store(CertSvcInstance instance,
                                            CertStoreType storeType,
                                            CertSvcString gname,
                                            char** certBuffer,
                                            size_t* certSize);

/**
 * This function will import a .pfx/.p12 file to specified store (WIFI, VPN, EMAIL).
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] storeType Refers to VPN_STORE / WIFI_STORE / EMAIL_STORE / SYSTEM_STORE / ALL_STORE.
 * @param[in] path Path of the certificate which needs to be imported.
 * @param[in] password Password to open the pfx/p12 file.
 * @param[in] alias Logical name for certificate bundle identification (can't be empty).
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT, CERTSVC_INVALID_STORE_TYPE
 */
int certsvc_pkcs12_import_from_file_to_store(CertSvcInstance instance,
                                             CertStoreType storeType,
                                             CertSvcString path,
                                             CertSvcString password,
                                             CertSvcString alias);

/**
 * This function will delete the certificate from the path specified present in the specified store.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] storeType Refers to VPN_STORE / WIFI_STORE / EMAIL_STORE / SYSTEM_STORE / ALL_STORE.
 * @param[in] gname Referred as group name, is the key for accessing the certificate.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT, CERTSVC_INVALID_STORE_TYPE
 */
int certsvc_pkcs12_delete_certificate_from_store(CertSvcInstance instance,
                                          CertStoreType storeType,
                                          CertSvcString gname);

/**
 * Query PKCS#12 storage to find out whenever new alias proposal is unique.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] storeType Refers to VPN_STORE / WIFI_STORE / EMAIL_STORE / SYSTEM_STORE / ALL_STORE.
 * @param[in] proposal Desired alias name.
 * @param[out] is_unique CERTSVC_TRUE (if there isn't such alias already) or CERTSVC_FALSE.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_pkcs12_check_alias_exists_in_store(CertSvcInstance instance,
                                         CertStoreType storeType,
                                         CertSvcString alias,
                                         int *is_unique);

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
int certsvc_pkcs12_load_certificate_list_from_store(CertSvcInstance instance,
                                                    CertStoreType storeType,
                                                    CertSvcString pfxIdString,
                                                    CertSvcCertificateList *certificateList);

/**
 * Gets the alias name for the gname passed.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] gname Certificate identification of pfx/pkcs file.
 * @param[out] alias Alias name for the given gname.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_pkcs12_get_alias_name_for_certificate_in_store(CertSvcInstance instance,
                                                    CertStoreType storeType,
                                                    CertSvcString gname,
                                                    char **alias);

#endif

#ifdef __cplusplus
}
#endif

#endif
