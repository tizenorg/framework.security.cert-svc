/*
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
 * @file        api_tests.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of main
 */

#include <cert-svc/cinstance.h>
#include <cert-svc/ccert.h>
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
#include <cert-svc/ccrl.h>
#include <cert-svc/cocsp.h>
#endif
#include <cert-svc/cpkcs12.h>
#include <cert-svc/cprimitives.h>

extern CertSvcInstance vinstance;
