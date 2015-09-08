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
 * @file        cocsp.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This is C api for ValidationCore.
 */
#ifndef _CERTSVC_OCSP_C_API_H_
#define _CERTSVC_OCSP_C_API_H_

#include <time.h>

#include <cert-svc/ccert.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CERTSVC_OCSP_GOOD                (1<<0)
#define CERTSVC_OCSP_REVOKED             (1<<1)
#define CERTSVC_OCSP_UNKNOWN             (1<<2)
#define CERTSVC_OCSP_VERIFICATION_ERROR  (1<<3)
#define CERTSVC_OCSP_NO_SUPPORT          (1<<4)
#define CERTSVC_OCSP_CONNECTION_FAILED   (1<<5)
#define CERTSVC_OCSP_ERROR               (1<<6)
/**
 * Implementation of ocsp call.
 *
 * Please note: to verify certificate you need certificate and his parrent.
 * This function will always verify chain_size-1 certificates from the chain.
 *
 * @param[in] chain Certificate to check.
 * @param[in] chain_size Size of certificate_array
 * @param[in] trusted Store with trusted certificates (additional certificates
 *                    that may by reqired during verification process).
 * @param[in] trusted_size Size of trusted certificate store.
 * @param[in] url Force OCSP to use specific server. Pass NULL to use OCSP server defined in certificate.
 * @param[out] status Bit field with description of chain validation.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_ocsp_check(CertSvcCertificate *chain,
                       int chainSize,
                       CertSvcCertificate *trusted,
                       int truestedSize,
                       const char *url,
                       int *status);

#ifdef __cplusplus
}
#endif

#endif
