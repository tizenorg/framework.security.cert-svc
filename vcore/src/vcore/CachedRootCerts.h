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
#ifndef TIZEN_FEATURE_CERT_SVC_STORE_CAPABILITY
#ifndef _CACHEDROOTCERTS_H_
#define _CACHEDROOTCERTS_H_

#include <glib.h>
#include <stdlib.h>
#include <cert-svc/ccert.h>

#ifdef __cplusplus
extern "C" {
#endif

int  c_certsvc_get_root_certificate_list(CertSvcStoreCertList** certList, int* length);
int  c_certsvc_free_root_certificate_list(CertSvcStoreCertList** certList);

#ifdef __cplusplus
}
#endif

#endif
#endif
