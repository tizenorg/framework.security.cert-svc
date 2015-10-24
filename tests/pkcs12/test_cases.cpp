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
 * @file        test_cases.cpp
 * @author      Jacek Migacz (j.migacz@samsung.com)
 * @version     1.0
 * @brief       PKCS#12 test cases.
 */
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dpl/test/test_runner.h>
#include <dpl/log/wrt_log.h>
#include <cert-svc/cinstance.h>
#include <cert-svc/ccert.h>
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
#include <cert-svc/ccrl.h>
#include <cert-svc/cocsp.h>
#endif
#include <cert-svc/cpkcs12.h>
#include <cert-svc/cerror.h>
#include <cert-svc/cprimitives.h>
#include <cert-service.h>

static CertSvcInstance instance;

#define CREATE_INSTANCE                                   \
  certsvc_instance_new(&instance);
#define FREE_INSTANCE                                     \
  certsvc_instance_free(instance);

#define ACCUM "/tmp/.test99_aux_test"

/*
 * author:      Jacek Migacz
 * test:        Import and remove pkcs container.
 * description: Importing and deleting pkcs container.
 * expect:      Import and removing container should return success.
 */
RUNNER_TEST(test01_import_and_remove_pkcs12_container) {
  const char path[] = "/opt/apps/widget/tests/pkcs12/test.p12";
  const char pass[] = "zaq12WSX";
  char *tmpn = "/opt/usr/media/testfilename"; // to fix prevent issue using unsecure API tmpnam 
  char *alias;
  int result;

  CREATE_INSTANCE
  CertSvcString Alias, Path, Pass;
//  RUNNER_ASSERT_MSG((tmpnam(tmpn)), "tmpnam(3) failed..");
  alias = strrchr(tmpn, '/');
  RUNNER_ASSERT_MSG(alias != NULL, "return null value from strrchr function.");
  ++alias;
  RUNNER_ASSERT_MSG(alias && *alias, "Invalid alias.");
  Alias.privateHandler = (char *)alias;
  Alias.privateLength = strlen(alias);
  Pass.privateHandler = (char *)pass;
  Pass.privateLength = strlen(pass);
  Path.privateHandler = (char *)path;
  Path.privateLength = strlen(path);
  result = certsvc_pkcs12_import_from_file(instance, Path, Pass, Alias);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_import_from_file failed.");

  int is_unique;
  result = certsvc_pkcs12_alias_exists(instance, Alias, &is_unique);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS && !is_unique, "certsvc_pkcs12_alias_exists failed.");

  char *buf;
  size_t size;
  result = certsvc_pkcs12_private_key_dup(instance, Alias, &buf, &size);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_private_key_dup failed.");
  certsvc_pkcs12_private_key_free(buf);

  result = certsvc_pkcs12_delete(instance, Alias);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_delete failed.");
  FREE_INSTANCE
}

/*
 * author:      Jacek Migacz
 * test:        Testing container password.
 * description: Checking if container has password.
 * expect:      Container should has password
 */
RUNNER_TEST(test02_pkcs12_has_password) {
  const char with[] = "/opt/apps/widget/tests/pkcs12/with_pass.p12";
  int has_pwd = 0;

  CREATE_INSTANCE
  CertSvcString File;
  File.privateHandler = (char *)with;
  File.privateLength = strlen(with);
  int result = certsvc_pkcs12_has_password(instance, File, &has_pwd);
  FREE_INSTANCE

  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS && has_pwd == CERTSVC_TRUE, "Error quering pkcs12/pfx container password.");
}

/*
 * author:      Jacek Migacz
 * test:        Testing container password.
 * description: Checking if container has password. 
 * expect:      Container should has not password.
 */
RUNNER_TEST(test03_pkcs12_has_password) {
  const char without[] = "/opt/apps/widget/tests/pkcs12/without_pass.p12";
  int has_pwd = 0;

  CREATE_INSTANCE
  CertSvcString File;
  File.privateHandler = (char *)without;
  File.privateLength = strlen(without);
  int result = certsvc_pkcs12_has_password(instance, File, &has_pwd);
  FREE_INSTANCE

  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS && has_pwd == CERTSVC_FALSE, "Error quering pkcs12/pfx container password.");
}

/*
 * author:      Jacek Migacz
 * test:        Testing pkcs extensions.
 * description: Loading certificates list from container.
 * expect:      Certyficates list from container should load correc.
 */

RUNNER_TEST(test04_PFX_extension) {
  const char path[] = "/opt/apps/widget/tests/pkcs12/eastest036.pfx";
  const char pass[] = "123456";
  char *tmpn = "/opt/usr/media/testfilename"; // to fix prevent issue using unsecure API tmpnam 
  char *alias;
  int result;

  CREATE_INSTANCE
  CertSvcString Alias, Path, Pass;
//  RUNNER_ASSERT_MSG((tmpnam(tmpn)), "tmpnam(3) failed..");
  alias = strrchr(tmpn, '/');
  RUNNER_ASSERT_MSG(alias != NULL, "strrcher operation error.");

  ++alias;

  RUNNER_ASSERT_MSG(alias && *alias, "Invalid alias.");
  Alias.privateHandler = (char *)alias;
  Alias.privateLength = strlen(alias);
  Pass.privateHandler = (char *)pass;
  Pass.privateLength = strlen(pass);
  Path.privateHandler = (char *)path;
  Path.privateLength = strlen(path);
  result = certsvc_pkcs12_import_from_file(instance, Path, Pass, Alias);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_import_from_file failed.");

  char *buf;
  size_t size;
  result = certsvc_pkcs12_private_key_dup(instance, Alias, &buf, &size);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_private_key_dup failed.");
  certsvc_pkcs12_private_key_free(buf);

  CertSvcCertificateList list;
  result = certsvc_pkcs12_load_certificate_list(instance, Alias, &list);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_load_certificate_list failed.");

  result = certsvc_pkcs12_delete(instance, Alias);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_delete failed.");
  FREE_INSTANCE
}

/*
 * author:      Jacek Migacz
 * test:        Intermediate certificate.
 * description: Getting details of certificates list from container. 
 * expect:      Certificates list is not empty and it is possible to get one certificate from list.
 */
RUNNER_TEST(test04_intermediate_certificate) {
  const char path[] = "/opt/apps/widget/tests/pkcs12/Maha.pfx";
  const char pass[] = "siso@123";
  const char alias[] = "maha";

  int cert_ret = CERTSVC_SUCCESS;
  CertSvcCertificateList cert_list;
  CertSvcString cert_path_str, cert_pass_str, cert_alias_str;
  CertSvcCertificate cert_output;
  certsvc_instance_new(&instance);

  cert_ret = certsvc_string_new(instance, path, strlen(path), &cert_path_str);
  RUNNER_ASSERT_MSG(cert_ret == CERTSVC_SUCCESS, "Failed to create new CertSvcString");

  cert_ret = certsvc_string_new(instance, pass, strlen(pass), &cert_pass_str);
  RUNNER_ASSERT_MSG(cert_ret == CERTSVC_SUCCESS, "Failed to create new CertSvcString");

  cert_ret = certsvc_string_new(instance, alias, strlen(alias), &cert_alias_str);
  RUNNER_ASSERT_MSG(cert_ret == CERTSVC_SUCCESS, "Failed to create new CertSvcString");

  int is_unique;
  cert_ret = certsvc_pkcs12_alias_exists(instance, cert_alias_str, &is_unique);
  RUNNER_ASSERT_MSG(cert_ret == CERTSVC_SUCCESS, "Failed certsvc_pkcs12_alias_exists");
  if(is_unique == CERTSVC_FALSE) {
      cert_ret = certsvc_pkcs12_delete(instance, cert_alias_str);
      RUNNER_ASSERT_MSG(cert_ret == CERTSVC_SUCCESS, "certsvc_pkcs12_delete failed.");
  }

  cert_ret = certsvc_pkcs12_import_from_file(instance, cert_path_str, cert_pass_str, cert_alias_str);
  RUNNER_ASSERT_MSG(cert_ret == CERTSVC_SUCCESS, "certsvc_pkcs12_import_from_file failed.");

  char *buf;
  size_t size;
  cert_ret = certsvc_pkcs12_private_key_dup(instance, cert_alias_str, &buf, &size);
  RUNNER_ASSERT_MSG(cert_ret == CERTSVC_SUCCESS, "certsvc_pkcs12_private_key_dup failed.");
  RUNNER_ASSERT_MSG(size != 0, "empty pkey buffer");
  certsvc_pkcs12_private_key_free(buf);

  int result;
  CertSvcStringList stringList;
  result = certsvc_pkcs12_get_id_list(instance, &stringList);
  RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certsvc_pkcs12_get_id_list");

  cert_ret = certsvc_pkcs12_load_certificate_list(instance, cert_alias_str, &cert_list);
  RUNNER_ASSERT_MSG(cert_ret == CERTSVC_SUCCESS, "Failed certsvc_pkcs12_load_certificate_list");

  int len;
  cert_ret = certsvc_certificate_list_get_length(cert_list, &len);
  RUNNER_ASSERT_MSG(cert_ret == CERTSVC_SUCCESS, "Failed certsvc_certificate_list_get_length");
  RUNNER_ASSERT_MSG(len != 0, "invalid list lenght");

  cert_ret = certsvc_certificate_list_get_one(cert_list, 0, &cert_output);
  RUNNER_ASSERT_MSG(cert_ret == CERTSVC_SUCCESS, "Failed certsvc_certificate_list_get_one");

  result = certsvc_pkcs12_delete(instance, cert_alias_str);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_delete failed.");
  FREE_INSTANCE
}

/*
 * author:      Jacek Migacz
 * test:        Testing in case of different gid
 * description: Another process is created and tries to acces key from container.
 * expect:      Another process should have access to the container.
 */
RUNNER_TEST(test04_different_gid) {
  const char path[] = "/opt/apps/widget/tests/pkcs12/eastest036.pfx";
  const char pass[] = "123456";
  const char alias[] = "__AUX__";
  FILE *stream;
  int result, status;
  CertSvcString Path, Pass, Alias;
  char buf;

  CREATE_INSTANCE

  result = certsvc_string_new(instance, path, strlen(path), &Path);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Failed to create new CertSvcString");
  result = certsvc_string_new(instance, pass, strlen(pass), &Pass);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Failed to create new CertSvcString");
  result = certsvc_string_new(instance, alias, strlen(alias), &Alias);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Failed to create new CertSvcString");
  result = certsvc_pkcs12_delete(instance, Alias);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_delete failed.");

  result = certsvc_pkcs12_import_from_file(instance, Path, Pass, Alias);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_import_from_file failed.");

  const char BINARY[] = "/usr/bin/cert-svc-tests-pkcs12-aux";
  switch(fork()) {
  case 0:
      execl(BINARY, BINARY, "--output=text", NULL);
	  break;
  case -1:
      RUNNER_ASSERT_MSG(true != false, "fork failed.");
      break;
  default:
      sleep(1);
      result = certsvc_pkcs12_delete(instance, Alias);
      RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_delete failed.");
      stream = fopen(ACCUM, "r");
      RUNNER_ASSERT_MSG(stream != NULL, "fopen failed.");
      RUNNER_ASSERT_MSG(1 == fread(&buf, 1, 1, stream), "error in fread");
      fclose(stream);
      RUNNER_ASSERT_MSG(buf == '1', "aux test faield.");
      wait(&status);
      unlink(ACCUM);
  }

  FREE_INSTANCE
}

/*
 * author:      Jacek Migacz
 * test:        Reading key from container.
 * description: Checking container key size.
 * expect:      Key size should be 256.
 */
RUNNER_TEST(test05_dup_EVP_PKEY) {
  const char path[] = "/opt/apps/widget/tests/pkcs12/eastest036.pfx";
  const char pass[] = "123456";
  char *tmpn = "/opt/usr/media/testfilename"; // to fix prevent issue using unsecure API tmpnam 
  char *alias;
  int result;

  CREATE_INSTANCE
  CertSvcString Alias, Path, Pass;
//  RUNNER_ASSERT_MSG((tmpnam(tmpn)), "tmpnam(3) failed..");
  alias = strrchr(tmpn, '/');
  RUNNER_ASSERT_MSG(alias != NULL, "return null value from strrchr function");
  ++alias;
  RUNNER_ASSERT_MSG(alias && *alias, "Invalid alias.");

  certsvc_string_new(instance, alias, strlen(alias), &Alias);
  certsvc_string_new(instance, pass, strlen(pass), &Pass);
  certsvc_string_new(instance, path, strlen(path), &Path);

  result = certsvc_pkcs12_import_from_file(instance, Path, Pass, Alias);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_import_from_file failed.");

  EVP_PKEY *pkey;
  result = certsvc_pkcs12_dup_evp_pkey(instance, Alias, &pkey);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_evp_pkey_dup failed");

  RUNNER_ASSERT_MSG(256 == EVP_PKEY_size(pkey), "wrong key size");
  certsvc_pkcs12_free_evp_pkey(pkey);

  FREE_INSTANCE
}

/*
 * author:      Jacek Migacz
 * test:        Reading key from container.
 * description: Checking container key size.
 * expect:      Key size should be 128.
 */
RUNNER_TEST(test06_dup_EVP_PKEY) {
    const char cpath[] = "/opt/apps/widget/tests/pkcs12/filip.pkcs12";
    const char cpass_import[] = "123456";
    const char calias[] = "alamakota";
    int result;

    CREATE_INSTANCE

    CertSvcString alias, path, passi;

    certsvc_string_new(instance, cpath, strlen(cpath), &path);
    certsvc_string_new(instance, cpass_import, strlen(cpass_import), &passi);
    certsvc_string_new(instance, calias, strlen(calias), &alias);

    result = certsvc_pkcs12_import_from_file(instance, path, passi, alias);
    RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_import_from_file failed");

    EVP_PKEY *pkey;
    result = certsvc_pkcs12_dup_evp_pkey(instance, alias, &pkey);
    RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_evp_pkey_dup failed");

    RUNNER_ASSERT_MSG(128 == EVP_PKEY_size(pkey), "wrong key size");
    certsvc_pkcs12_free_evp_pkey(pkey);

    result = certsvc_pkcs12_delete(instance, alias);
    RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_delete failed.");

    FREE_INSTANCE
}

/*
 * author: Janusz Kozerski <j.kozerski@samsung.com>
 * test: Installation pkcs12 with more than 2 certificates.
 * description: Test certsvc_pkcs12_import_from_file function for specify pkcs12 file.
 * expect: Successful install and successful uninstall.
 */
RUNNER_TEST(test07_pkcs_with_3_certs) {
    const char cpath[] = "/opt/apps/widget/tests/pkcs12/tizen_test_certs.p12";
    const char cpass_import[] = "password";
    const char calias[] = "Tizen test cert";
    int result;

    CREATE_INSTANCE

    CertSvcString alias, path, pass;

    certsvc_string_new(instance, cpath, strlen(cpath), &path);
    certsvc_string_new(instance, cpass_import, strlen(cpass_import), &pass);
    certsvc_string_new(instance, calias, strlen(calias), &alias);

    result = certsvc_pkcs12_import_from_file(instance, path, pass, alias);
    RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_import_from_file failed.");

    result = certsvc_pkcs12_delete(instance, alias);
    RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_delete failed.");

    FREE_INSTANCE
}

