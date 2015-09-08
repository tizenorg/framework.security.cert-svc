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
 * @file        aux_test.cpp
 * @author      Jacek Migacz (j.migacz@samsung.com)
 * @version     1.0
 * @brief       Auxiliary PKCS#12 test case.
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dpl/test/test_runner.h>
#include <dpl/log/log.h>
#include <cert-svc/cinstance.h>
#include <cert-svc/ccert.h>
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
#include <cert-svc/ccrl.h>
#include <cert-svc/cocsp.h>
#endif
#include <cert-svc/cpkcs12.h>
#include <cert-svc/cerror.h>
#include <cert-service.h>

#define ACCUM "/tmp/.test99_aux_test"

RUNNER_TEST(test99_aux_test) {
  const char alias[] = "__AUX__";
  int result;
  CertSvcInstance instance;
  CertSvcString Alias;
  char *buf;
  size_t size;
  FILE *stream;

  certsvc_instance_new(&instance);
  result = certsvc_string_new(instance, alias, strlen(alias), &Alias);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Failed to create new CertSvcString");

  result = certsvc_pkcs12_private_key_dup(instance, Alias, &buf, &size);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_private_key_dup failed.");
  RUNNER_ASSERT_MSG(size != 0, "empty pkey buffer");

  certsvc_pkcs12_private_key_free(buf);
  stream = fopen(ACCUM, "w");
  RUNNER_ASSERT_MSG(stream != NULL, "fopen failed.");

  fwrite("1", 1, 1, stream);
  fclose(stream);
  certsvc_instance_free(instance);
}
