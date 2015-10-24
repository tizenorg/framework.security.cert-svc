/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        new_test_cases.cpp
 * @author      Madhan A K (madhan.ak@samsung.com)
 * @version     1.0
 * @brief       PKCS#12 test cases.
 */

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dpl/test/test_runner.h>
#include <dpl/log/wrt_log.h>
#include <cert-svc/cinstance.h>
#include <cert-svc/ccert.h>
#include <glib.h>
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
#include <cert-svc/ccrl.h>
#include <cert-svc/cocsp.h>
#endif
#include <cert-svc/cpkcs12.h>
#include <cert-svc/cerror.h>
#include <cert-svc/cprimitives.h>
#include <cert-service.h>
#include <cert-service-debug.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <time.h>

static CertSvcInstance instance;

#define CREATE_INSTANCE                                   \
  certsvc_instance_new(&instance);
#define FREE_INSTANCE                                     \
  certsvc_instance_free(instance);

/* Getting the certificate list from system_store */
RUNNER_TEST(CERTSVC_PKCS12_1001_certsvc_get_root_cert_list) {

	CertStoreType storeType = SYSTEM_STORE;
	CertSvcStoreCertList* certList = NULL;
	CertSvcStoreCertList* tmpNode = NULL;
	int length = 0;
	int result;
	int count = 0;
	CREATE_INSTANCE

	//start time
	clock_t tic = clock();
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, storeType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from system store failed");
	clock_t toc = clock();
	//time end
	LOGD("Elapsed: %f seconds", (double)(toc - tic) / CLOCKS_PER_SEC);
	if(result == CERTSVC_SUCCESS)
	{
	  LOGD("cert-store and status working [result=%d]", result);

	  tmpNode = certList;
	  while(tmpNode != NULL)
	  {
		  count++;
		  LOGD("[certList->title=%s]", tmpNode->title);
		  LOGD("[certList->status=%d]", tmpNode->status);
		  LOGD("[certList->storeType=%d]", tmpNode->storeType);

		  tmpNode = tmpNode->next;
	  }

	  result = certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	  RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Freeing certificate list from system store failed");

	  LOGD("NUMBER OF CERT DETAILS=[%d]", count);
	  LOGD("[length=%d]", length);
	}

	FREE_INSTANCE
}

/* Set the status of the certificate to disabled/enabled in system store and get the status */
RUNNER_TEST(CERTSVC_PKCS12_1002_certsvc_set_cert_to_disabled_and_get_status_for_system_store) {

	char *gname = "f61bff45.0";
	CertStoreType storeType = SYSTEM_STORE;
	CertStatus Status;
	int status = -1;
	int result;
	CertSvcString Alias;

	CREATE_INSTANCE

	Alias.privateHandler = gname;
	Alias.privateLength = strlen((const char*)gname);

	result = certsvc_pkcs12_get_certificate_status_from_store(instance, storeType, Alias, &status);
	LOGD("Certificate status for %s is : %d",gname, status);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Get certificate status from system store failed.");

	Status=DISABLED;
	result = certsvc_pkcs12_set_certificate_status_to_store(instance, storeType, DISABLED, Alias, Status);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Set certificate status to system store failed.");

	result = certsvc_pkcs12_get_certificate_status_from_store(instance, storeType, Alias, &status);
	LOGD("Certificate status for %s is : %d",gname, status);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Get certificate status from system store failed.");

	Status=ENABLED;
	result = certsvc_pkcs12_set_certificate_status_to_store(instance, storeType, DISABLED, Alias, Status);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Set certificate status to system store failed.");

	result = certsvc_pkcs12_get_certificate_status_from_store(instance, storeType, Alias, &status);
	LOGD("Certificate status for %s is : %d",gname, status);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Get certificate status from system store failed.");

	FREE_INSTANCE
}

/* Install a CRT file to individual stores */
RUNNER_TEST(CERTSVC_PKCS12_1003_add_pem_file_in_individual_store) {

	char path[] = "/opt/share/cert-svc/tests/wifi-server.pem";
	CertSvcStoreCertList* certList = NULL;
	CertSvcStoreCertList* tmpNode = NULL;
	CertSvcStoreCertList* tmp = NULL;
	char* pass = NULL;
	CertStoreType type;
	int result;
	int length = 0;
	int count = 0;

	CertSvcStoreCertList* certList1 = NULL;
	CertSvcString buffer1, gname;
	CertSvcString buffer2;
	const char *temp = NULL;
	CertSvcCertificate certificate;

	CREATE_INSTANCE
	CertSvcString Alias, Path, Pass;

	Pass.privateHandler = pass;
	Path.privateHandler = path;
	Path.privateLength = strlen(path);

	type = WIFI_STORE;
	Alias.privateHandler = "PEM-wifi-server-1";
	Alias.privateLength = strlen(Alias.privateHandler);
	result = certsvc_pkcs12_import_from_file_to_store(instance, type, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Importing PEM file to WIFI store failed.");

	type = VPN_STORE;
	Alias.privateHandler = "PEM-wifi-server-2";
	Alias.privateLength = strlen(Alias.privateHandler);
	result = certsvc_pkcs12_import_from_file_to_store(instance, type, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Importing PEM file to VPN store failed.");

	type = EMAIL_STORE;
	Alias.privateHandler = "PEM-wifi-server-3";
	Alias.privateLength = strlen(Alias.privateHandler);
	result = certsvc_pkcs12_import_from_file_to_store(instance, type, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Importing PEM file to EMAIL store failed.");

	type = (CertStoreType) (WIFI_STORE | VPN_STORE | EMAIL_STORE);
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, type, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from system store failed");

	if(result == CERTSVC_SUCCESS)
	{
	  LOGD("cert-store and status working [result=%d]", result);

	  tmpNode = certList;
	  while(tmpNode != NULL)
	  {
		  count++;
		  LOGD("[certList->title=%s]", tmpNode->title);
		  LOGD("[certList->storeType=%d]", tmpNode->storeType);
		  LOGD("[certList->status=%d]", tmpNode->status);
		  tmp = tmpNode;
		  tmpNode = tmpNode->next;
	  }
	  result = certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	  RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Freeing certificate list from system store failed");

	  LOGD("NUMBER OF CERT DETAILS=[%d]", count);
	  LOGD("[length=%d]", length);
	}

	certList = NULL;
	type = (CertStoreType) (WIFI_STORE | VPN_STORE | EMAIL_STORE);
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, type, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from store failed.");
	certList1=certList;
	count = 0;
	while(certList!=NULL)
	{
		gname.privateHandler = (char *)certList->gname;
		gname.privateLength = strlen(certList->gname);
		LOGD("gname in processing : %s",certList->gname);
		result = certsvc_pkcs12_get_certificate_from_store(instance, certList->storeType, certList->gname, &certificate);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to get certificate from store.");

		result = certsvc_certificate_get_string_field(certificate, CERTSVC_SUBJECT, &buffer1);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to get string field.");

		result = certsvc_certificate_get_string_field(certificate, CERTSVC_ISSUER_COMMON_NAME, &buffer2);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to get string field.");

		certsvc_string_to_cstring(buffer1, &temp, &length);
		if (temp!=NULL) LOGD("Subject : %s",temp);
		certsvc_string_to_cstring(buffer2, &temp, &length);
		if (temp!=NULL) LOGD("Issuer : %s",temp);

		certsvc_string_free(buffer1);
		certsvc_string_free(buffer2);
		certsvc_certificate_free(certificate);
		certList = certList->next;
		count++;
	}
	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList1);
	if (certList1 != NULL)
		LOGD("certList is not NULL.");

	LOGD("Total records processed : %d",count);
	certList=NULL;
	certList1=NULL;

	FREE_INSTANCE
}

/* Installing pem file in all store at once */
RUNNER_TEST(CERTSVC_PKCS12_1004_add_pem_file_in_all_store) {

	const char path[] = "/opt/share/cert-svc/tests/wifi-server.pem";
	CertSvcStoreCertList* certList = NULL;
	CertSvcStoreCertList* tmpNode = NULL;
	CertSvcStoreCertList* tmp = NULL;
	char* pass = NULL;
	char *alias = "PEM-wifi-server-all-store";
	CertStoreType type;
	int result;
	int count = 0;
	int length = 0;

	CREATE_INSTANCE
	CertSvcString Alias, Path, Pass;

	Alias.privateHandler = alias;
	Alias.privateLength = strlen(alias);
	Pass.privateHandler = pass;
	Path.privateHandler = (char *)path;
	Path.privateLength = strlen(path);

	type = (CertStoreType) (VPN_STORE | EMAIL_STORE | WIFI_STORE);
	result = certsvc_pkcs12_import_from_file_to_store(instance, type, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Importing PEM file to all store failed.");

	type = (CertStoreType) (WIFI_STORE | VPN_STORE | EMAIL_STORE);
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, type, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from system store failed");

	if(result == CERTSVC_SUCCESS)
	{
	  LOGD("cert-store and status working [result=%d]", result);

	  tmpNode = certList;
	  while(tmpNode != NULL)
	  {
		  count++;
		  LOGD("[certList->title=%s]", tmpNode->title);
		  LOGD("[certList->storeType=%d]", tmpNode->storeType);
		  LOGD("[certList->status=%d]", tmpNode->status);
		  tmp = tmpNode;
		  tmpNode = tmpNode->next;
	  }
	  result = certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	  RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Freeing certificate list from system store failed");

	  LOGD("NUMBER OF CERT DETAILS=[%d]", count);
	  LOGD("[length=%d]", length);
	}

	FREE_INSTANCE
}

/* Install a CRT file to individual stores */
RUNNER_TEST(CERTSVC_PKCS12_1005_add_crt_file_in_individual_store) {

	const char path[] = "/opt/share/cert-svc/tests/Testing.crt";
	CertSvcStoreCertList* certList = NULL;
	CertSvcStoreCertList* tmpNode = NULL;
	CertSvcStoreCertList* tmp = NULL;
	char* pass = NULL;
	char *alias = "CRT-TestingCRT1";
	CertStoreType type;
	int result;
	int length = 0;
	int count = 0;

	CertSvcStoreCertList* certList1 = NULL;
	CertSvcString buffer1, gname;
	CertSvcString buffer2;
	const char *temp = NULL;
	CertSvcCertificate certificate;

	CREATE_INSTANCE
	CertSvcString Alias, Path, Pass;

	Alias.privateHandler = alias;
	Alias.privateLength = strlen(alias);
	Pass.privateHandler = pass;
	Path.privateHandler = (char *)path;
	Path.privateLength = strlen(path);

	type = WIFI_STORE;
	result = certsvc_pkcs12_import_from_file_to_store(instance, type, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Importing CRT file to WIFI store failed.");

	type = VPN_STORE;
	result = certsvc_pkcs12_import_from_file_to_store(instance, type, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Importing CRT file to VPN store failed.");

	type = EMAIL_STORE;
	result = certsvc_pkcs12_import_from_file_to_store(instance, type, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Importing CRT file to EMAIL store failed.");

	type = (CertStoreType) (WIFI_STORE | VPN_STORE | EMAIL_STORE);
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, type, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from system store failed");

	if(result == CERTSVC_SUCCESS)
	{
	  LOGD("cert-store and status working [result=%d]", result);

	  tmpNode = certList;
	  while(tmpNode != NULL)
	  {
		  count++;
		  LOGD("[certList->title=%s]", tmpNode->title);
		  LOGD("[certList->storeType=%d]", tmpNode->storeType);
		  LOGD("[certList->status=%d]", tmpNode->status);
		  tmp = tmpNode;
		  tmpNode = tmpNode->next;
	  }
	  result = certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	  RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Freeing certificate list from system store failed");

	  LOGD("NUMBER OF CERT DETAILS=[%d]", count);
	  LOGD("[length=%d]", length);
	}

	certList = NULL;
	type = (CertStoreType) (WIFI_STORE | VPN_STORE | EMAIL_STORE);
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, type, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from store failed.");
	certList1=certList;
	count = 0;
	while(certList!=NULL)
	{
		gname.privateHandler = (char *)certList->gname;
		gname.privateLength = strlen(certList->gname);
		LOGD("gname in processing : %s",certList->gname);
		result = certsvc_pkcs12_get_certificate_from_store(instance, certList->storeType, certList->gname, &certificate);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to get certificate from store.");

		result = certsvc_certificate_get_string_field(certificate, CERTSVC_SUBJECT, &buffer1);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to get string field.");

		result = certsvc_certificate_get_string_field(certificate, CERTSVC_ISSUER_COMMON_NAME, &buffer2);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to get string field.");

		certsvc_string_to_cstring(buffer1, &temp, &length);
		if (temp!=NULL) LOGD("Subject : %s",temp);
		certsvc_string_to_cstring(buffer2, &temp, &length);
		if (temp!=NULL) LOGD("Issuer : %s",temp);

		certsvc_string_free(buffer1);
		certsvc_string_free(buffer2);
		certsvc_certificate_free(certificate);
		certList = certList->next;
		count++;
	}
	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList1);
	if (certList1 != NULL)
		LOGD("certList is not NULL.");

	LOGD("Total records processed : %d",count);
	certList=NULL;
	certList1=NULL;

	FREE_INSTANCE
}

/* Install a CRT file to all store at once */
RUNNER_TEST(CERTSVC_PKCS12_1006_add_crt_file_in_all_store) {

	const char path[] = "/opt/share/cert-svc/tests/Testing.crt";
	CertSvcStoreCertList* certList = NULL;
	CertSvcStoreCertList* tmpNode = NULL;
	CertSvcStoreCertList* tmp = NULL;
	char* pass = NULL;
	char *alias = "CRT-TestingCRT1-all-store";
	CertStoreType type;
	int result;
	int count = 0;
	int length = 0;

	CREATE_INSTANCE
	CertSvcString Alias, Path, Pass;

	Alias.privateHandler = alias;
	Alias.privateLength = strlen(alias);
	Pass.privateHandler = pass;
	Path.privateHandler = (char *)path;
	Path.privateLength = strlen(path);

	type = (CertStoreType )(WIFI_STORE | VPN_STORE | EMAIL_STORE);
	result = certsvc_pkcs12_import_from_file_to_store(instance, type, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Importing CRT file to all store failed.");

	type = (CertStoreType) (WIFI_STORE | VPN_STORE | EMAIL_STORE);
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, type, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from system store failed");

	if(result == CERTSVC_SUCCESS)
	{
	  LOGD("cert-store and status working [result=%d]", result);

	  tmpNode = certList;
	  while(tmpNode != NULL)
	  {
		  count++;
		  LOGD("[certList->title=%s]", tmpNode->title);
		  LOGD("[certList->storeType=%d]", tmpNode->storeType);
		  LOGD("[certList->status=%d]", tmpNode->status);
		  tmp = tmpNode;
		  tmpNode = tmpNode->next;
	  }
	  result = certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	  RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Freeing certificate list from system store failed");

	  LOGD("NUMBER OF CERT DETAILS=[%d]", count);
	  LOGD("[length=%d]", length);
	}

	FREE_INSTANCE
}

/* Import a P12 file to individual store */
RUNNER_TEST(CERTSVC_PKCS12_1007_install_p12_file_to_individual_store) {

	const char path[] = "/opt/share/cert-svc/tests/wifiuser.p12";
	CertSvcStoreCertList* certList = NULL;
	CertSvcStoreCertList* tmpNode = NULL;
	CertSvcStoreCertList* tmp = NULL;
	const char pass[] = "wifi";
	char *alias = "P12-WifiUser";
	CertStoreType storeType;
	int result;
	int length = 0;
	int count = 0;

	CREATE_INSTANCE
	CertSvcString Alias, Path, Pass;

	Alias.privateHandler = (char *)alias;
	Alias.privateLength = strlen(alias);
	Pass.privateHandler = (char *)pass;
	Pass.privateLength = strlen(pass);
	Path.privateHandler = (char *)path;
	Path.privateLength = strlen(path);

/*
	result = certsvc_pkcs12_import_from_file(instance, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_import_from_file failed.");
*/

	storeType = WIFI_STORE;
	result = certsvc_pkcs12_import_from_file_to_store(instance, storeType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Importing p12 file to WIFI store failed.");

	storeType = VPN_STORE;
	result = certsvc_pkcs12_import_from_file_to_store(instance, storeType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Importing p12 file to VPN store failed.");

	storeType = EMAIL_STORE;
	result = certsvc_pkcs12_import_from_file_to_store(instance, storeType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Importing p12 file to EMAIL store failed.");

	storeType = (CertStoreType) (WIFI_STORE | VPN_STORE | EMAIL_STORE);
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, storeType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from system store failed");

	if(result == CERTSVC_SUCCESS)
	{
	  LOGD("cert-store and status working [result=%d]", result);

	  tmpNode = certList;
	  while(tmpNode != NULL)
	  {
		  count++;
		  LOGD("[certList->title=%s]", tmpNode->title);
		  LOGD("[certList->storeType=%d]", tmpNode->storeType);
		  LOGD("[certList->status=%d]", tmpNode->status);
		  tmp = tmpNode;
		  tmpNode = tmpNode->next;
	  }
	  result = certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	  RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Freeing certificate list from system store failed");

	  LOGD("NUMBER OF CERT DETAILS=[%d]", count);
	  LOGD("[length=%d]", length);
	}

	FREE_INSTANCE
}

/* Import a P12 file to all store */
RUNNER_TEST(CERTSVC_PKCS12_1008_install_p12_file_to_all_store) {

	const char path[] = "/opt/share/cert-svc/tests/wifiuser.p12";
	CertSvcStoreCertList* certList = NULL;
	CertSvcStoreCertList* tmpNode = NULL;
	CertSvcStoreCertList* tmp = NULL;
	const char pass[] = "wifi";
	char *alias = "P12-WifiUser-all-store";
	CertStoreType storeType;
	int result;
	int length = 0;
	int count =0;

	CREATE_INSTANCE
	CertSvcString Alias, Path, Pass;

	Alias.privateHandler = (char *)alias;
	Alias.privateLength = strlen(alias);
	Pass.privateHandler = (char *)pass;
	Pass.privateLength = strlen(pass);
	Path.privateHandler = (char *)path;
	Path.privateLength = strlen(path);

	storeType = (CertStoreType )(WIFI_STORE | VPN_STORE | EMAIL_STORE);
	result = certsvc_pkcs12_import_from_file_to_store(instance, storeType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Importing p12 file to WIFI store failed.");

	storeType = (CertStoreType) (WIFI_STORE | VPN_STORE | EMAIL_STORE);
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, storeType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from system store failed");

	if(result == CERTSVC_SUCCESS)
	{
	  LOGD("cert-store and status working [result=%d]", result);

	  tmpNode = certList;
	  while(tmpNode != NULL)
	  {
		  count++;
		  LOGD("[certList->title=%s]", tmpNode->title);
		  LOGD("[certList->storeType=%d]", tmpNode->storeType);
		  LOGD("[certList->status=%d]", tmpNode->status);
		  tmp = tmpNode;
		  tmpNode = tmpNode->next;
	  }
	  result = certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	  RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Freeing certificate list from system store failed");

	  LOGD("NUMBER OF CERT DETAILS=[%d]", count);
	  LOGD("[length=%d]", length);
	}

	FREE_INSTANCE
}

/* Import a P12 file to individual store */
RUNNER_TEST(CERTSVC_PKCS12_1009_install_pfx_file_to_individual_store) {

	const char path[] = "/opt/share/cert-svc/tests/wifiserver.pfx";
	CertSvcStoreCertList* certList = NULL;
	CertSvcStoreCertList* tmpNode = NULL;
	CertSvcStoreCertList* tmp = NULL;
	const char pass[] = "wifi";
	char *alias = "PFX-WifiServer";
	CertStoreType storeType;
	int result;
	int count = 0;
	int length = 0;

	CREATE_INSTANCE
	CertSvcString Alias, Path, Pass;

	Alias.privateHandler = (char *)alias;
	Alias.privateLength = strlen(alias);
	Pass.privateHandler = (char *)pass;
	Pass.privateLength = strlen(pass);
	Path.privateHandler = (char *)path;
	Path.privateLength = strlen(path);

	storeType = WIFI_STORE;
	result = certsvc_pkcs12_import_from_file_to_store(instance, storeType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Importing PFX file to WIFI store failed.");

	storeType = VPN_STORE;
	result = certsvc_pkcs12_import_from_file_to_store(instance, storeType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Importing PFX file to VPN store failed.");

	storeType = EMAIL_STORE;
	result = certsvc_pkcs12_import_from_file_to_store(instance, storeType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Importing PFX file to EMAIL store failed.");

	storeType = (CertStoreType) (WIFI_STORE | VPN_STORE | EMAIL_STORE);
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, storeType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from system store failed");

	if(result == CERTSVC_SUCCESS)
	{
	  LOGD("cert-store and status working [result=%d]", result);

	  tmpNode = certList;
	  while(tmpNode != NULL)
	  {
		  count++;
		  LOGD("[certList->title=%s]", tmpNode->title);
		  LOGD("[certList->storeType=%d]", tmpNode->storeType);
		  LOGD("[certList->status=%d]", tmpNode->status);
		  tmp = tmpNode;
		  tmpNode = tmpNode->next;
	  }
	  result = certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	  RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Freeing certificate list from system store failed");

	  LOGD("NUMBER OF CERT DETAILS=[%d]", count);
	  LOGD("[length=%d]", length);
	}

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1010_install_pfx_file_to_all_store) {

	const char path[] = "/opt/share/cert-svc/tests/wifiserver.pfx";
	const char pass[] = "wifi";
	char *alias = "PFX-WifiServer-all-store";
	CertStoreType storeType;
	CertSvcStoreCertList* certList = NULL;
	CertSvcStoreCertList* tmpNode = NULL;
	CertSvcStoreCertList* tmp = NULL;
	int length = 0;
	int count = 0;
	int result;

	CREATE_INSTANCE
	CertSvcString Alias, Path, Pass;

	Alias.privateHandler = (char *)alias;
	Alias.privateLength = strlen(alias);
	Pass.privateHandler = (char *)pass;
	Pass.privateLength = strlen(pass);
	Path.privateHandler = (char *)path;
	Path.privateLength = strlen(path);

	storeType = (CertStoreType) (VPN_STORE | EMAIL_STORE | WIFI_STORE);
	result = certsvc_pkcs12_import_from_file_to_store(instance, storeType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Importing PFX file to WIFI store failed.");

	storeType = (CertStoreType) (WIFI_STORE | VPN_STORE | EMAIL_STORE);
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, storeType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from system store failed");

	if(result == CERTSVC_SUCCESS)
	{
	  LOGD("cert-store and status working [result=%d]", result);

	  tmpNode = certList;
	  while(tmpNode != NULL)
	  {
		  count++;
		  LOGD("[certList->title=%s]", tmpNode->title);
		  LOGD("[certList->storeType=%d]", tmpNode->storeType);
		  LOGD("[certList->status=%d]", tmpNode->status);
		  tmp = tmpNode;
		  tmpNode = tmpNode->next;
	  }
	  result = certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	  RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Freeing certificate list from system store failed");

	  LOGD("NUMBER OF CERT DETAILS=[%d]", count);
	  LOGD("[length=%d]", length);
	}

	FREE_INSTANCE
}

/* Getting all end user & root certificate list from WIFI,VPN,EMAIL store */
RUNNER_TEST(CERTSVC_PKCS12_1011_get_all_end_user_certificate_from_store) {

	CertSvcStoreCertList* certList = NULL;
	CertSvcStoreCertList* tmpNode = NULL;
	CertStoreType storeType = (CertStoreType) (WIFI_STORE);
	int result;
	int length;

	CREATE_INSTANCE

	LOGD("*************Getting all end user certificates*************");
	result = certsvc_pkcs12_get_end_user_certificate_list_from_store(instance, storeType, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting end user certificate list from store failed.");
	tmpNode=certList;
	while(tmpNode!=NULL)
	{
		LOGD("[certList->title=%s]", tmpNode->title);
		LOGD("[certList->storeType=%d]", tmpNode->storeType);
		LOGD("[certList->status=%d]", tmpNode->status);
		tmpNode = tmpNode->next;
	}
	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	if (certList != NULL) {
		LOGD("certList is not NULL.");
	}
	certList = NULL;
	tmpNode = NULL;

	storeType = (CertStoreType) (VPN_STORE);
	result = certsvc_pkcs12_get_end_user_certificate_list_from_store(instance, storeType, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting end user certificate list from store failed.");
	tmpNode=certList;
	while(tmpNode!=NULL)
	{
		LOGD("[certList->title=%s]", tmpNode->title);
		LOGD("[certList->storeType=%d]", tmpNode->storeType);
		LOGD("[certList->status=%d]", tmpNode->status);
		tmpNode = tmpNode->next;
	}
	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	if (certList != NULL) {
		LOGD("certList is not NULL.");
	}
	certList = NULL;
	tmpNode = NULL;

	storeType = (CertStoreType) (EMAIL_STORE);
	result = certsvc_pkcs12_get_end_user_certificate_list_from_store(instance, storeType, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting end user certificate list from store failed.");
	tmpNode=certList;
	while(tmpNode!=NULL)
	{
		LOGD("[certList->title=%s]", tmpNode->title);
		LOGD("[certList->storeType=%d]", tmpNode->storeType);
		LOGD("[certList->status=%d]", tmpNode->status);
		tmpNode = tmpNode->next;
	}
	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	if (certList != NULL) {
		LOGD("certList is not NULL.");
	}
	certList = NULL;
	tmpNode = NULL;

	LOGD("*************Getting all root certificates*************");
	storeType = (CertStoreType) (WIFI_STORE);
	result = certsvc_pkcs12_get_root_certificate_list_from_store(instance, storeType, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting end user certificate list from store failed.");
	tmpNode=certList;
	while(tmpNode!=NULL)
	{
		LOGD("[certList->title=%s]", tmpNode->title);
		LOGD("[certList->storeType=%d]", tmpNode->storeType);
		LOGD("[certList->status=%d]", tmpNode->status);
		tmpNode = tmpNode->next;
	}
	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	if (certList != NULL) {
		LOGD("certList is not NULL.");
	}
	certList = NULL;
	tmpNode = NULL;

	storeType = (CertStoreType) (VPN_STORE);
	result = certsvc_pkcs12_get_root_certificate_list_from_store(instance, storeType, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting end user certificate list from store failed.");
	tmpNode=certList;
	while(tmpNode!=NULL)
	{
		LOGD("[certList->title=%s]", tmpNode->title);
		LOGD("[certList->storeType=%d]", tmpNode->storeType);
		LOGD("[certList->status=%d]", tmpNode->status);
		tmpNode = tmpNode->next;
	}
	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	if (certList != NULL) {
		LOGD("certList is not NULL.");
	}
	certList = NULL;
	tmpNode = NULL;

	storeType = (CertStoreType) (EMAIL_STORE);
	result = certsvc_pkcs12_get_root_certificate_list_from_store(instance, storeType, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting end user certificate list from store failed.");
	tmpNode=certList;
	while(tmpNode!=NULL)
	{
		LOGD("[certList->title=%s]", tmpNode->title);
		LOGD("[certList->storeType=%d]", tmpNode->storeType);
		LOGD("[certList->status=%d]", tmpNode->status);
		tmpNode = tmpNode->next;
	}
	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	if (certList != NULL) {
		LOGD("certList is not NULL.");
	}
	certList = NULL;
	tmpNode = NULL;

	FREE_INSTANCE
}

/* Delete all certificate from WIFI,VPN,EMAIL store */
RUNNER_TEST(CERTSVC_PKCS12_1012_delete_all_cert_from_multiple_store) {

	CertSvcStoreCertList* certList = NULL;
	CertSvcStoreCertList* certList1 = NULL;
	CertStoreType storeType = (CertStoreType) (WIFI_STORE | VPN_STORE | EMAIL_STORE);
	int result;
	int length;
	CertSvcString gname;

	CREATE_INSTANCE

	result = certsvc_pkcs12_get_certificate_list_from_store(instance, storeType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from store failed.");
	certList1=certList;
	while(certList1!=NULL)
	{
		gname.privateHandler = (char *)certList1->gname;
		gname.privateLength = strlen(certList1->gname);
		LOGD("Filename to delete : %s",certList1->gname);
		result = certsvc_pkcs12_delete_certificate_from_store(instance, (CertStoreType) certList1->storeType, gname);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Deleting certificate from store failed.");
		certList1 = certList1->next;
	}
	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	certList=NULL;

	FREE_INSTANCE
}

/* Import the file to one store and try to get the certlist from all store */
RUNNER_TEST(CERTSVC_PKCS12_1013_install_pfx_file_to_one_store_and_get_list_from_multiple_store) {

	const char path[] = "/opt/share/cert-svc/tests/wifiserver.pfx";
	const char pass[] = "wifi";
	char *alias = "PFX-WifiServer-one-store";
	CertStoreType storeType;
	CertSvcStoreCertList* certList = NULL;
	CertSvcStoreCertList* tmpNode = NULL;
	CertSvcStoreCertList* tmp = NULL;
	int length = 0;
	int count = 0;
	int result = -1;
	gboolean exists = FALSE;

	CREATE_INSTANCE
	CertSvcString Alias, Path, Pass;

	Alias.privateHandler = (char *)alias;
	Alias.privateLength = strlen(alias);
	Pass.privateHandler = (char *)pass;
	Pass.privateLength = strlen(pass);
	Path.privateHandler = (char *)path;
	Path.privateLength = strlen(path);

	storeType = (CertStoreType) (VPN_STORE | WIFI_STORE | EMAIL_STORE);
	result = certsvc_pkcs12_check_alias_exists_in_store(instance, storeType, Alias, &exists);
	if (exists==TRUE) {
		/* installing the pfx in one store and getting the list from multiple store */
		storeType = (CertStoreType) ( EMAIL_STORE );
		result = certsvc_pkcs12_import_from_file_to_store(instance, storeType, Path, Pass, Alias);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Importing PFX file to WIFI store failed.");

		storeType = (CertStoreType) ( VPN_STORE | WIFI_STORE  );
		result = certsvc_pkcs12_import_from_file_to_store(instance, storeType, Path, Pass, Alias);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Importing PFX file to WIFI store failed.");

		storeType = (CertStoreType) ( VPN_STORE | WIFI_STORE | EMAIL_STORE);
		result = certsvc_pkcs12_get_certificate_list_from_store(instance, storeType, DISABLED, &certList, &length);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from system store failed");

		if(result == CERTSVC_SUCCESS)
		{
		  LOGD("cert-store and status working [result=%d]", result);

		  tmpNode = certList;
		  while(tmpNode != NULL)
		  {
			  count++;
			  LOGD("[certList->title=%s]", tmpNode->title);
			  LOGD("[certList->storeType=%d]", tmpNode->storeType);
			  LOGD("[certList->status=%d]", tmpNode->status);
			  tmp = tmpNode;
			  tmpNode = tmpNode->next;
		  }
		  result = certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
		  RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Freeing certificate list from system store failed");

		  LOGD("NUMBER OF CERT DETAILS=[%d]", count);
		  LOGD("[length=%d]", length);
		}
	}

	FREE_INSTANCE
}

/* Set the status of the certificate to disabled and trying to delete store */
RUNNER_TEST(CERTSVC_PKCS12_1014_installing_pfx_without_password_to_individual_store) {

	const char path[] = "/opt/share/cert-svc/tests/without_pass.p12";
	const char pass[] = "";
	char *alias = "PFX-WifiServer-without-password";
	CertStoreType storeType;
	int result;
	gboolean exists = FALSE;

	CREATE_INSTANCE
	CertSvcString Alias, Path, Pass;

	Alias.privateHandler = (char *)alias;
	Alias.privateLength = strlen(alias);
	Pass.privateHandler = (char *)pass;
	Pass.privateLength = strlen(pass);
	Path.privateHandler = (char *)path;
	Path.privateLength = strlen(path);

	storeType = (CertStoreType) (VPN_STORE | WIFI_STORE | EMAIL_STORE);
	result = certsvc_pkcs12_check_alias_exists_in_store(instance, storeType, Alias, &exists);
	if (exists==TRUE) {
		storeType = (CertStoreType) (VPN_STORE | WIFI_STORE | EMAIL_STORE);
		result = certsvc_pkcs12_import_from_file_to_store(instance, storeType, Path, Pass, Alias);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Importing PFX file to WIFI store failed.");
	}

	FREE_INSTANCE
}

/* Get certificate from WIFI,VPN,EMAIL store */
RUNNER_TEST(CERTSVC_PKCS12_1015_get_certificate_from_store) {

	CertSvcStoreCertList* certList = NULL;
	CertSvcStoreCertList* certList1 = NULL;
	CertStoreType storeType = (CertStoreType) (WIFI_STORE | VPN_STORE | EMAIL_STORE);
	int result;
	int length;
	CertSvcString buffer1, gname;
	CertSvcString buffer2;
	const char *temp = NULL;
	CertSvcCertificate certificate;

	CREATE_INSTANCE

	result = certsvc_pkcs12_get_certificate_list_from_store(instance, storeType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from store failed.");
	certList1=certList;
	while(certList!=NULL)
	{
		gname.privateHandler = (char *)certList->gname;
		gname.privateLength = strlen(certList->gname);
		LOGD("gname in processing : %s",certList->gname);
		LOGD("Store Type : %d",certList->storeType);
		result = certsvc_pkcs12_get_certificate_from_store(instance, certList->storeType, certList->gname, &certificate);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to get certificate from store.");

		result = certsvc_certificate_get_string_field(certificate, CERTSVC_SUBJECT, &buffer1);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to get string field.");

		certsvc_string_to_cstring(buffer1, &temp, &length);
		LOGD("Subject : %s",temp);

		result = certsvc_certificate_get_string_field(certificate, CERTSVC_ISSUER_COMMON_NAME, &buffer2);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to get string field.");

		certsvc_string_to_cstring(buffer2, &temp, &length);
		LOGD("Issuer common name : %s",temp);

		certsvc_string_free(buffer1);
		certsvc_string_free(buffer2);
		certsvc_certificate_free(certificate);
		certList = certList->next;
	}
	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList1);
	if (certList1 != NULL) {
		LOGD("certList is not NULL.");
	}
	certList=NULL;
	certList1=NULL;

	FREE_INSTANCE
}

/* Get certificate from system store */
RUNNER_TEST(CERTSVC_PKCS12_1016_get_certificate_from_system_store) {

	CertSvcStoreCertList* certList = NULL;
	CertSvcStoreCertList* certList1 = NULL;
	CertStoreType storeType = (CertStoreType) (SYSTEM_STORE);
	int result = CERTSVC_SUCCESS;
	int length = 0;
	int count = 0;
	CertSvcString buffer1, gname;
	CertSvcString buffer2;
	const char *temp = NULL;
	CertSvcCertificate certificate;

	CREATE_INSTANCE

	result = certsvc_pkcs12_get_certificate_list_from_store(instance, storeType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from store failed.");
	certList1=certList;
	while(certList!=NULL)
	{
		gname.privateHandler = (char *)certList->gname;
		gname.privateLength = strlen(certList->gname);
		LOGD("gname in processing : %s",certList->gname);
		result = certsvc_pkcs12_get_certificate_from_store(instance, certList->storeType, certList->gname, &certificate);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to get certificate from store.");

		result = certsvc_certificate_get_string_field(certificate, CERTSVC_SUBJECT, &buffer1);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to get string field.");

		result = certsvc_certificate_get_string_field(certificate, CERTSVC_ISSUER_COMMON_NAME, &buffer2);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to get string field.");

		certsvc_string_to_cstring(buffer1, &temp, &length);
		if (temp!=NULL) LOGD("Subject : %s",temp);
		certsvc_string_to_cstring(buffer2, &temp, &length);
		if (temp!=NULL) LOGD("Issuer : %s",temp);

		certsvc_string_free(buffer1);
		certsvc_string_free(buffer2);
		certsvc_certificate_free(certificate);
		certList = certList->next;
		count++;
	}
	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList1);
	if (certList1 != NULL) {
		LOGD("certList is not NULL.");
	}

	LOGD("Total records processed : %d",count);
	certList=NULL;
	certList1=NULL;

	FREE_INSTANCE
}

/* Load certificate list form store for a certificate */
RUNNER_TEST(CERTSVC_PKCS12_1017_load_cert_list_from_store) {

	CertStoreType storeType;
	CertSvcCertificateList certList;
	CertSvcStoreCertList* certList1 = NULL;
	CertSvcCertificate cert;
	int result = CERTSVC_SUCCESS;
	int length = 0;
	int i=0;
	int certListlength = 0;
	const char *temp = NULL;
	CertSvcString buffer1,buffer2, gname;

	CREATE_INSTANCE

	storeType = (CertStoreType) (VPN_STORE);
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, storeType, DISABLED, &certList1, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from store failed.");
	while(certList1!=NULL)
	{
		gname.privateHandler = (char *)certList1->gname;
		gname.privateLength = strlen(certList1->gname);
		LOGD("gname in processing : %s",certList1->gname);

		result = certsvc_pkcs12_load_certificate_list_from_store(instance, storeType, gname, &certList);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Load certificate list form store failed.");

		result = certsvc_certificate_list_get_length(certList, &certListlength);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Get certificate list get length failed.");

		LOGD("Certificate List Length = %d", certListlength);
		for(i=0; i<certListlength; i++)
		{
			result = certsvc_certificate_list_get_one(certList, i, &cert);
			RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "certsvc_certificate_list_get_one returned not CERTSVC_SUCCESS");

			result = certsvc_certificate_get_string_field(cert, CERTSVC_SUBJECT, &buffer1);
			RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to get string field.");

			certsvc_string_to_cstring(buffer1, &temp, &length);
			LOGD("Subject : %s",temp);

			result = certsvc_certificate_get_string_field(cert, CERTSVC_ISSUER_COMMON_NAME, &buffer2);
			RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to get string field.");

			certsvc_string_to_cstring(buffer2, &temp, &length);
			LOGD("Issuer common name : %s",temp);
		}
		break; // Should run for only one time //
	}

	FREE_INSTANCE
}

/* Load certificate list form store for a certificate */
RUNNER_TEST(CERTSVC_PKCS12_1018_get_duplicate_private_key) {

	CertStoreType storeType;
	CertSvcStoreCertList* certList1 = NULL;
	FILE *fp = NULL;
	int result = CERTSVC_SUCCESS;
	int length = 0;
	CertSvcString gname;
	gchar *privatekey_path = NULL;
	EVP_PKEY *privatekey = NULL;

	CREATE_INSTANCE

	storeType = (CertStoreType) (VPN_STORE);
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, storeType, DISABLED, &certList1, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from store failed.");
	while(certList1!=NULL)
	{
		gname.privateHandler = (char *)certList1->gname;
		gname.privateLength = strlen(certList1->gname);
		LOGD("gname in processing : %s",certList1->gname);

		result = certsvc_pkcs12_dup_evp_pkey_from_store(instance, storeType, gname, &privatekey);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting duplicate private key from store failed.");

		privatekey_path = g_strdup_printf("%s", "/opt/share/cert-svc/pkcs12/temp.txt");
		if ((fp = fopen(privatekey_path, "w")) == NULL) {
			result = CERTSVC_FAIL;
			RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to open file for writing.");
		}

		result = PEM_write_PrivateKey(fp, privatekey, NULL, NULL, 0, NULL, NULL);
		RUNNER_ASSERT_MSG(result!=0, "Failed to write private key onto file.");
		fclose(fp);

		certsvc_pkcs12_free_evp_pkey(privatekey);

		break; // Should run for only one time //
	}

	FREE_INSTANCE
}

/* Get certificate from system store */
RUNNER_TEST(CERTSVC_PKCS12_1019_check_alias_exists) {

	char *alias = "PFX-WifiServer-without-password";
	CertStoreType storeType;
	int result = CERTSVC_SUCCESS;
	gboolean exists = FALSE;

	CREATE_INSTANCE
	CertSvcString Alias;

	Alias.privateHandler = (char *)alias;
	Alias.privateLength = strlen(alias);
	storeType = (CertStoreType) (VPN_STORE | WIFI_STORE | EMAIL_STORE);
	result = certsvc_pkcs12_check_alias_exists_in_store(instance, storeType, Alias, &exists);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from store failed.");

	FREE_INSTANCE
}

/* Set the status of the certificate to disabled/enabled in wifi,vpn,email store */
RUNNER_TEST(CERTSVC_PKCS12_1020_certsvc_set_cert_to_disabled_and_get_status_for_individual_store) {

	CertSvcStoreCertList* certList = NULL;
	CertSvcStoreCertList* tmpNode = NULL;
	int array[3]={VPN_STORE,WIFI_STORE,EMAIL_STORE};
	int result = CERTSVC_SUCCESS;
	CertSvcString Alias;
	CertStatus Status;
	int status = -1;
	int length = 0;
	int count = 0;
    int i;

	CREATE_INSTANCE

	for(int j=0;j<3;j++)
	{
        i = array[j];
        LOGD("........ j=%d, i=%d", j, i);
		if (i==VPN_STORE) LOGD("Setting the certificate status to disabled in VPN store");
		else if (i==WIFI_STORE) LOGD("Setting the certificate status to disabled in WIFI store");
		else if (i==EMAIL_STORE) LOGD("Setting the certificate status to disabled in EMAIL store");

		result = certsvc_pkcs12_get_certificate_list_from_store(instance, (CertStoreType)i, DISABLED, &certList, &length);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from store failed.");
		tmpNode = certList;
		LOGD("Total Length : %d",length);
		while(certList!=NULL)
		{
			LOGD("Filename in processing : %s",certList->gname);
			count++;
			Alias.privateHandler = certList->gname;
			Alias.privateLength = strlen((const char*)certList->gname);

			result = certsvc_pkcs12_get_certificate_status_from_store(instance, (CertStoreType)i, Alias, &status);
			LOGD("Certificate status for %s is : %s",certList->gname, (status==0)? "Disabled": "Enabled");
			RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Get certificate status from system store failed.");

			Status=DISABLED;
			result = certsvc_pkcs12_set_certificate_status_to_store(instance, (CertStoreType)i, DISABLED, Alias, Status);
			RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Set certificate status to system store failed.");

			result = certsvc_pkcs12_get_certificate_status_from_store(instance, (CertStoreType)i, Alias, &status);
			LOGD("Certificate status for %s is : %s",certList->gname, (status==0)? "Disabled": "Enabled");
			RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Get certificate status from system store failed.");

			Status=ENABLED;
			result = certsvc_pkcs12_set_certificate_status_to_store(instance, (CertStoreType)i, DISABLED, Alias, Status);
			RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Set certificate status to system store failed.");

			result = certsvc_pkcs12_get_certificate_status_from_store(instance, (CertStoreType)i, Alias, &status);
			LOGD("Certificate status for %s is : %s",certList->gname, (status==0)? "Disabled": "Enabled");
			RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Get certificate status from system store failed.");

			certList = certList->next;
		}

		certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &tmpNode);
	}
	LOGD("Length : %d",count);

	FREE_INSTANCE
}

/* Negative test case */
/* Install a PEM file to invalid store  */
RUNNER_TEST(CERTSVC_PKCS12_1021_add_pem_file_to_invalid_store) {

	const char path[] = "/opt/share/cert-svc/tests/wifi-server.pem";
	char* pass = NULL;
	char *alias = "PFX-WifiServer-one-store";
	int result;
	CertStoreType storeType = (CertStoreType) (-1);
	CertSvcString Alias, Path, Pass;

	CREATE_INSTANCE

	Alias.privateHandler = alias;
	Alias.privateLength = strlen(alias);
	Pass.privateHandler = pass;
	Path.privateHandler = (char *)path;
	Path.privateLength = strlen(path);

	result = certsvc_pkcs12_import_from_file_to_store(instance, storeType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result==CERTSVC_INVALID_STORE_TYPE, "Importing certifcate with existing alias to WIFI store failed.");

	result = certsvc_pkcs12_import_from_file_to_store(instance, storeType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result==CERTSVC_INVALID_STORE_TYPE, "Importing certifcate with existing alias to VPN store failed.");

	result = certsvc_pkcs12_import_from_file_to_store(instance, storeType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result==CERTSVC_INVALID_STORE_TYPE, "Importing certifcate with existing alias to EMAIL store failed.");

	/* Installing a PEM certificate to system store should fail */
	storeType = SYSTEM_STORE;
	result = certsvc_pkcs12_import_from_file_to_store(instance, storeType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Importing PEM file to EMAIL store failed.");

	/* Removing certificate to system store should fail */
	result = certsvc_pkcs12_delete_certificate_from_store(instance, storeType, Alias);
	LOGD("result = %d",result);
	RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Deleting certificate from store failed.");


	FREE_INSTANCE
}

/* Set the status of the certificate to disabled/enabled from invalid store */
RUNNER_TEST(CERTSVC_PKCS12_1022_certsvc_set_cert_to_disabled_and_get_status_for_invalid_store) {

	char* gname = "eb375c3e.0";
	CertStoreType storeType = (CertStoreType) (DISABLED);
	CertStatus Status;
	int status = -1;
	int result;
	CertSvcString Alias;

	CREATE_INSTANCE

	Alias.privateHandler = gname;
	Alias.privateLength = strlen((const char*)gname);

	/* getting status from a invalid store should fail */
	result = certsvc_pkcs12_get_certificate_status_from_store(instance, storeType, Alias, &status);
	RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Get certificate status from system store failed.");

	/* setting status to a invalid store should fail */
	Status=DISABLED;
	result = certsvc_pkcs12_set_certificate_status_to_store(instance, storeType, DISABLED, Alias, Status);
	RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Set certificate status to system store failed.");

	/* getting status from a invalid store should fail */
	result = certsvc_pkcs12_get_certificate_status_from_store(instance, storeType, Alias, &status);
	RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Get certificate status from system store failed.");

	/* setting status to a invalid store should fail */
	Status=ENABLED;
	result = certsvc_pkcs12_set_certificate_status_to_store(instance, storeType, DISABLED, Alias, Status);
	RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Set certificate status to system store failed.");

	/* setting status to a invalid store should fail */
	result = certsvc_pkcs12_get_certificate_status_from_store(instance, storeType, Alias, &status);
	RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Get certificate status from system store failed.");


	FREE_INSTANCE
}

/* Set the status of the certificate to disabled/enabled in wifi,vpn,email store */
RUNNER_TEST(CERTSVC_PKCS12_1023_certsvc_set_cert_to_disabled_and_get_status_for_invalid_store) {

	CertStoreType storeType =  (CertStoreType) (0);
	CertSvcStoreCertList* certList = NULL;
	CertStatus Status;
	int status = -1;
	int length;
	int result;
	CertSvcString Alias;

	CREATE_INSTANCE

	/* Getting certificate list from invalid store should fail */
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, storeType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Getting certificate list from store failed.");
	while(certList!=NULL)
	{
		LOGD("Filename in processing : %s",certList->gname);

		Alias.privateHandler = certList->gname;
		Alias.privateLength = strlen((const char*)certList->gname);

		result = certsvc_pkcs12_get_certificate_status_from_store(instance, storeType, Alias, &status);
		RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Get certificate status from system store failed.");

		Status=DISABLED;
		result = certsvc_pkcs12_set_certificate_status_to_store(instance, storeType, DISABLED, Alias, Status);
		RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Set certificate status to system store failed.");

		result = certsvc_pkcs12_get_certificate_status_from_store(instance, storeType, Alias, &status);
		RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Get certificate status from system store failed.");

		Status=ENABLED;
		result = certsvc_pkcs12_set_certificate_status_to_store(instance, storeType, DISABLED, Alias, Status);
		RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Set certificate status to system store failed.");

		result = certsvc_pkcs12_get_certificate_status_from_store(instance, storeType, Alias, &status);
		RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Get certificate status from system store failed.");

		certList = certList->next;
	}

	FREE_INSTANCE
}

/* Intsalling an invalid crt file to valid store & invalid store*/
RUNNER_TEST(CERTSVC_PKCS12_1024_certsvc_set_and_get_for_invalid_store) {

	const char path[] = "/opt/share/cert-svc/tests/Invalidcrt.crt";
	char* pass = NULL;
	char *alias = "TestingCRT1";
	CertStoreType type;
	int result;

	CREATE_INSTANCE
	CertSvcString Alias, Path, Pass;

	Alias.privateHandler = alias;
	Alias.privateLength = strlen(alias);
	Pass.privateHandler = pass;
	Path.privateHandler = (char *)path;
	Path.privateLength = strlen(path);

	/* Installing an invalid CRT file to valid store should fail */
	type = WIFI_STORE;
	result = certsvc_pkcs12_import_from_file_to_store(instance, type, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Importing CRT file to WIFI store failed.");

	/* Installing an invalid CRT file to valid store should fail */
	type = VPN_STORE;
	result = certsvc_pkcs12_import_from_file_to_store(instance, type, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Importing CRT file to VPN store failed.");

	/* Installing an invalid CRT file to valid store should fail */
	type = EMAIL_STORE;
	result = certsvc_pkcs12_import_from_file_to_store(instance, type, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Importing CRT file to EMAIL store failed.");

	/* Installing an invalid CRT file to valid store should fail */
	type = (CertStoreType) 0;
	result = certsvc_pkcs12_import_from_file_to_store(instance, type, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Importing CRT file to EMAIL store failed.");

	FREE_INSTANCE
}

/* Import a invalid P12 file to individual and all store */
RUNNER_TEST(CERTSVC_PKCS12_1025_install_invalid_pfx_file_to_individual_and_all_store) {

	const char path[] = "/opt/share/cert-svc/tests/test.pfx";
	const char pass[] = "wifi";
	char *alias = "WifiServer-123";
	CertStoreType storeType;
	int result;

	CREATE_INSTANCE
	CertSvcString Alias, Path, Pass;

	Alias.privateHandler = (char *)alias;
	Alias.privateLength = strlen(alias);
	Pass.privateHandler = (char *)pass;
	Pass.privateLength = strlen(pass);
	Path.privateHandler = (char *)path;
	Path.privateLength = strlen(path);

	/* importing p12/pfx to system store should fail */
	storeType = SYSTEM_STORE;
	result = certsvc_pkcs12_import_from_file_to_store(instance, storeType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Importing PFX file to WIFI store failed.");

	/* Importing invalid pfx file to valid store should fail */
	storeType = WIFI_STORE;
	result = certsvc_pkcs12_import_from_file_to_store(instance, storeType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Importing PFX file to WIFI store failed.");

	/* Importing invalid pfx file to valid store should fail */
	storeType = VPN_STORE;
	result = certsvc_pkcs12_import_from_file_to_store(instance, storeType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Importing PFX file to VPN store failed.");

	/* Importing invalid pfx file to valid store should fail */
	storeType = EMAIL_STORE;
	result = certsvc_pkcs12_import_from_file_to_store(instance, storeType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Importing PFX file to EMAIL store failed.");

	/* Importing invalid pfx file to valid store should fail */
	storeType = (CertStoreType) (EMAIL_STORE | VPN_STORE | WIFI_STORE);
	result = certsvc_pkcs12_import_from_file_to_store(instance, storeType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Importing PFX file to EMAIL store failed.");

	FREE_INSTANCE
}

/* Set the status of the certificate to disabled/enabled in wifi,vpn,email store */
RUNNER_TEST(CERTSVC_PKCS12_1026_deleting_a_certificate_from_invalid_store) {

	CertStoreType storeType =  (CertStoreType) (WIFI_STORE);
	CertSvcStoreCertList* certList = NULL;
	CertStatus Status;
	int status = -1;
	int length;
	int result;
	CertSvcString Alias;

	CREATE_INSTANCE

	/* Getting certificate list from invalid store should fail */
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, storeType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from store failed.");
	while(certList!=NULL)
	{
		LOGD("Filename in processing : %s",certList->gname);

		Alias.privateHandler = certList->gname;
		Alias.privateLength = strlen((const char*)certList->gname);

		result = certsvc_pkcs12_get_certificate_status_from_store(instance, (CertStoreType)-1, Alias, &status);
		RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Get certificate status from system store failed.");

		Status=DISABLED;
		result = certsvc_pkcs12_set_certificate_status_to_store(instance, (CertStoreType)-1, DISABLED, Alias, Status);
		RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Set certificate status to system store failed.");

		result = certsvc_pkcs12_get_certificate_status_from_store(instance, (CertStoreType)-1, Alias, &status);
		RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Get certificate status from system store failed.");

		Status=ENABLED;
		result = certsvc_pkcs12_set_certificate_status_to_store(instance, (CertStoreType)-1, DISABLED, Alias, Status);
		RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Set certificate status to system store failed.");

		result = certsvc_pkcs12_get_certificate_status_from_store(instance, (CertStoreType)-1, Alias, &status);
		RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Get certificate status from system store failed.");

		certList = certList->next;
	}

	FREE_INSTANCE
}

#define EAP_TLS_USER_CERT_PATH   "user_cert.pem"
#define EAP_TLS_PATH             "/tmp/"
#define EAP_TLS_CA_CERT_PATH     "ca_cert.pem"
#define EAP_TLS_PRIVATEKEY_PATH  "privatekey.pem"

/* Set the status of the certificate to disabled/enabled in wifi,vpn,email store */
RUNNER_TEST(CERTSVC_PKCS12_1027_get_alias_name_from_gname_from_store) {

	CertStoreType storeType =  (CertStoreType) (WIFI_STORE);
	CertSvcStoreCertList* certList = NULL;
	CertSvcCertificate user_certificate;
	CertSvcCertificateList cert_list;
	CertSvcCertificate ca_certificate;
	CertSvcCertificate *selected_certificate = NULL;
	int length;
	int result;
	int count=1;
	int validity;
	int cert_counts = 0;
	CertSvcString Alias;
	char *alias = NULL;
	X509 *x509 = NULL;
	FILE *fp = NULL;
	EVP_PKEY *privatekey = NULL;
	gchar *privatekey_path = NULL;
	gchar *ca_cert_path = NULL;
	gchar *user_cert_path = NULL;
	int cert_index = 0;

	CREATE_INSTANCE

	/* Getting certificate list from invalid store should fail */
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, storeType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from store failed.");
	while(certList!=NULL) {
		LOGD("Filename in processing : %s",certList->gname);

		Alias.privateHandler = certList->gname;
		Alias.privateLength = strlen((const char*)certList->gname);

		result = certsvc_pkcs12_get_alias_name_for_certificate_in_store(instance, certList->storeType, Alias, &alias);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting alias name from gname failed.");

		LOGD("Gname passed : %s , Alias : %s",certList->gname, alias);

        result = certsvc_pkcs12_load_certificate_list_from_store(instance, certList->storeType, Alias, &cert_list);
        RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "failed to certsvc_pkcs12_load_certificate_list");

        result = certsvc_certificate_list_get_length(cert_list, &cert_counts);
        RUNNER_ASSERT_MSG(cert_counts >= 1, "there is no certificates");
        LOGD("cert counts: %d	", cert_counts);

        selected_certificate = g_try_new0(CertSvcCertificate, cert_counts);
        RUNNER_ASSERT_MSG(selected_certificate != NULL, "failed to allocate memory");

        result = certsvc_certificate_list_get_one(cert_list, 0, &user_certificate);
        RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "failed to certsvc_certificate_list_get_one");

		result = certsvc_certificate_dup_x509(user_certificate, &x509);
		LOGD("Return value : %d",result);

        user_cert_path = g_strdup_printf("/opt/share/cert-svc/pkcs12/file_%d", count++);
        fp = fopen(user_cert_path, "w");
        RUNNER_ASSERT_MSG(fp != NULL, "Failed to open the file for writing");

        LOGD("user-cert_path : %s",user_cert_path);
		if (count==5) break;

        result = PEM_write_X509(fp, x509);
        fclose(fp);
        certsvc_certificate_free_x509(x509);
		certList = certList->next;

		cert_index = cert_counts - 1;
		selected_certificate[0] = user_certificate;

        ca_cert_path = g_strdup_printf("%s%s_%s", EAP_TLS_PATH, certList->gname, EAP_TLS_CA_CERT_PATH);
        LOGD("ca-cert_path : %s",ca_cert_path);
        while (cert_index) {
                LOGD("....cert_index: %d",cert_index);
                result = certsvc_certificate_list_get_one(cert_list, cert_index, &ca_certificate);
                RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to certsvc_certificate_list_get_one");

                selected_certificate[cert_counts-cert_index] = ca_certificate;
                cert_index--;

                result = certsvc_certificate_dup_x509(ca_certificate, &x509);

                fp = fopen(ca_cert_path, "a");
                RUNNER_ASSERT_MSG(fp != NULL, "Failed to open the file for writing");

                result = PEM_write_X509(fp, x509);
                fclose(fp);
                certsvc_certificate_free_x509(x509);
        }
        result = certsvc_certificate_verify(selected_certificate[0], selected_certificate, cert_counts, NULL, 0, &validity);
        RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to verify ca_certificate");
        RUNNER_ASSERT_MSG(validity != 0, "Invalid certificate");

        result = certsvc_pkcs12_dup_evp_pkey_from_store(instance, WIFI_STORE, Alias, &privatekey);
        RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to duplicate the private key for a certificate from wifi store");

        privatekey_path = g_strdup_printf("%s%s_%s", EAP_TLS_PATH, certList->gname, EAP_TLS_PRIVATEKEY_PATH);

        fp = fopen(privatekey_path, "w");
        RUNNER_ASSERT_MSG(fp != NULL, "Failed to open the file for writing");

        result = PEM_write_PrivateKey(fp, privatekey, NULL, NULL, 0, NULL, NULL);
        LOGD("result : %d",result);
        fclose(fp);
        certsvc_pkcs12_free_evp_pkey(privatekey);
	}

	FREE_INSTANCE
}

/* Set the status of the certificate to disabled/enabled in wifi,vpn,email store */
RUNNER_TEST(CERTSVC_PKCS12_1028_certsvc_set_cert_to_disabled_and_get_status_for_individual_store) {

	CertSvcStoreCertList* certList = NULL;
	CertSvcStoreCertList* tmpNode = NULL;
	int array[3]={VPN_STORE,WIFI_STORE,EMAIL_STORE};
	int result = CERTSVC_SUCCESS;
	CertSvcString Alias;
	CertStatus Status;
	int status = -1;
	int length = 0;
	int count = 0;
    int i;

	CREATE_INSTANCE

	for(int j=0;j<3;j++)
	{
        i = array[j];
		if (i==VPN_STORE) LOGD("Setting the certificate status to disabled in VPN store");
		else if (i==WIFI_STORE) LOGD("Setting the certificate status to disabled in WIFI store");
		else if (i==EMAIL_STORE) LOGD("Setting the certificate status to disabled in EMAIL store");

		result = certsvc_pkcs12_get_certificate_list_from_store(instance, (CertStoreType)i, ENABLED, &certList, &length);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Getting certificate list from store failed.");
		tmpNode = certList;
		LOGD("Total Length : %d",length);
		while(certList!=NULL)
		{
			LOGD("Filename in processing : %s",certList->gname);
			count++;
			Alias.privateHandler = certList->gname;
			Alias.privateLength = strlen((const char*)certList->gname);

			result = certsvc_pkcs12_get_certificate_status_from_store(instance, (CertStoreType)i, Alias, &status);
			LOGD("Certificate status for %s is : %s",certList->gname, (status==0)? "Disabled": "Enabled");
			RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Get certificate status from store failed.");

			Status=DISABLED;
			result = certsvc_pkcs12_set_certificate_status_to_store(instance, (CertStoreType)i, ENABLED, Alias, Status);
			RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Set certificate status to store failed.");

			status = DISABLED;
			result = certsvc_pkcs12_get_certificate_status_from_store(instance, (CertStoreType)i, Alias, &status);
			LOGD("Certificate status for %s is : %s",certList->gname, (status==0)? "Disabled": "Enabled");
			RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Get certificate status from store failed.");

			Status=ENABLED;
			result = certsvc_pkcs12_set_certificate_status_to_store(instance, (CertStoreType)i, ENABLED, Alias, Status);
			RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Set certificate status to store failed.");

			status = DISABLED;
			result = certsvc_pkcs12_get_certificate_status_from_store(instance, (CertStoreType)i, Alias, &status);
			LOGD("Certificate status for %s is : %s",certList->gname, (status==0)? "Disabled": "Enabled");
			RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Get certificate status from store failed.");

			Status=DISABLED;
			result = certsvc_pkcs12_set_certificate_status_to_store(instance, (CertStoreType)i, DISABLED, Alias, Status);
			RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Set certificate status to store failed.");

			status = DISABLED;
			result = certsvc_pkcs12_get_certificate_status_from_store(instance, (CertStoreType)i, Alias, &status);
			LOGD("Certificate status for %s is : %s",certList->gname, (status==0)? "Disabled": "Enabled");
			RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Get certificate status from store failed.");

			Status=ENABLED;
			result = certsvc_pkcs12_set_certificate_status_to_store(instance, (CertStoreType)i, DISABLED, Alias, Status);
			RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Set certificate status to store failed.");

			status = DISABLED;
			result = certsvc_pkcs12_get_certificate_status_from_store(instance, (CertStoreType)i, Alias, &status);
			LOGD("Certificate status for %s is : %s",certList->gname, (status==0)? "Disabled": "Enabled");
			RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Get certificate status from store failed.");

			certList = certList->next;
		}

		certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &tmpNode);
	}
	LOGD("Length : %d",count);

	FREE_INSTANCE
}
