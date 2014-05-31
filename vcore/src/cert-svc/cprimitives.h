/**
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
/*
 * @file        vcore_api_extension.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This is C api for ValidationCore.
 */
#ifndef _CERTSVC_C_API_EXTENDED_H_
#define _CERTSVC_C_API_EXTENDED_H_

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <cert-svc/ccert.h>
#include <cert-svc/cstring.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This will return pointer to X509 base openssl struct. This struct must be release by function
 * certsvc_certificate_free_x509.
 *
 * vcore_instance_free or vcore_instance_reset will not free memory allocated by this function!
 *
 * @param[in] certificate Pointer to certificate.
 * @param[out] cert Duplicate of certificate.
 * @return CERTSVC_SUCCESS, CERTSVC_WRONG_ARGUMENT, CERTSVC_FAIL
 */
int certsvc_certificate_dup_x509(CertSvcCertificate certificate, X509** cert);

/**
 * Release X509 struct allocated by certsvc_certificate_new_x509_copy function.
 *
 * @param[in] x509_copy Pointer to openssl struct.
 */
void certsvc_certificate_free_x509(X509 *x509_copy);

/**
 * This will return pointer to EVP_PKEY base openssl struct. This struct must
 * be release with function certsvc_pkcs12_free_evp_pkey
 *
 * @param[in] instance
 * @param[in] alias Pkcs12 identificator.
 * @param[out] pkey Duplicate of private key.
 * @return CERTSVC_SUCCESS, CERT_FAIL
 */

int certsvc_pkcs12_dup_evp_pkey(CertSvcInstance instance,
                                CertSvcString alias,
                                EVP_PKEY** pkey);

void certsvc_pkcs12_free_evp_pkey(EVP_PKEY* pkey);

#ifdef __cplusplus
}
#endif

#endif
