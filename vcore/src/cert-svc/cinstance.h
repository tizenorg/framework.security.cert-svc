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
 * @file        cinstance.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This is part of C api for ValidationCore.
 */
#ifndef _CERTSVC_CINSTANCE_H_
#define _CERTSVC_CINSTANCE_H_

#include <cert-svc/cerror.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CertSvcInstance_t {
    void *privatePtr;
} CertSvcInstance;

/**
 * Allocate internal data of CertSvc library and put it in the CertSvcInstance structure.
 * Initialize Openssl interanal structures, initialize all structures required by libsoup
 * (libsoup is used by ocps and crl functions).
 *
 * @param[out] instance Pointer to CertSvcInstance.
 * @return CERTSVC_SUCCESS or CERTSVC_FAIL.
 */
int certsvc_instance_new(CertSvcInstance *instance);

/**
 * This function will free all allocated data. All certificate identificator will
 * be released and all strings allocated by certsvc_certificate_get_string field will be
 * released also.
 *
 * This fucntion does not release CertSvcInstnace!
 *
 * Plese note: It is safe to use this function after use certsvc_string_free.
 *
 * @param[in] instance CertSvcInstance object.
 */
void certsvc_instance_reset(CertSvcInstance instance);

/**
 * This function will free all allocated data. All certificate identificator will
 * be released and all strings allocated by certsvc_certificate_get_string field will be
 * released also.
 *
 * This fucntion also release CertSvcInstnace!
 *
 * Please note: It is safe use this function after use certsvc_string_free.
 *
 * @param[in] instance CertSvcInstance object
 */
void certsvc_instance_free(CertSvcInstance instance);

#ifdef __cplusplus
}
#endif

#endif // _CERTSVC_CINSTANCE_H_

