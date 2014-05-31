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
 * @file        ccrl.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This is part of C api for ValidationCore.
 */
#ifndef _CERTSVC_CCRL_H_
#define _CERTSVC_CCRL_H_

#include <time.h>

#include <cert-svc/ccert.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CERTSVC_CRL_GOOD                 (1<<0)
#define CERTSVC_CRL_REVOKED              (1<<1)
#define CERTSVC_CRL_VERIFICATION_ERROR   (1<<3)
#define CERTSVC_CRL_NO_SUPPORT           (1<<4)

typedef void (*CertSvcCrlCacheWrite)(
    const char *distributionPoint,
    const char *body,
    int bodySize,
    time_t nextUpdateTime,
    void *userParam);

typedef int (*CertSvcCrlCacheRead)(
    const char *distributionPoint,
    char **body,
    int *bodySize,
    time_t *nextUpdateTime,
    void *userParam);

typedef void (*CertSvcCrlFree)(
    char *buffer,
    void *userParam);

void certsvc_crl_cache_functions(
    CertSvcInstance instance,
    CertSvcCrlCacheWrite writePtr,
    CertSvcCrlCacheRead readPtr,
    CertSvcCrlFree freePtr);

int certsvc_crl_check(
    CertSvcCertificate certificate,
    CertSvcCertificate *trustedStore,
    int storeSize,
    int force,
    int *status,
    void *userParam);

#ifdef __cplusplus
}
#endif

#endif

