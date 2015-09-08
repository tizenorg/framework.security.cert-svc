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




#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
#include <cert-service.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <cert-service-util.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#define	CERT_FILE_ROOT_CA			"/opt/share/cert-svc/tests/orig_c/data/ocsp/root_ca.der"
#define	CERT_FILE_SECOND_CA			"/opt/share/cert-svc/tests/orig_c/data/ocsp/second_ca.der"
#define	CERT_FILE_SIGNER_AIA		"/opt/share/cert-svc/tests/orig_c/data/ocsp/aia_signer.der"
#define	CERT_FILE_SIGNER_REVOKED	"/opt/share/cert-svc/tests/orig_c/data/ocsp/rev_signer.der"
#define	CERT_FILE_SIGNER_NOAIA		"/opt/share/cert-svc/tests/orig_c/data/ocsp/noaia_signer.der"

#define CERT_FILE_NO_ROOT_CERT      "/opt/share/cert-svc/tests/orig_c/data/ocsp/noroot_cert.pem"

#define CERT_FILE_REAL_LEVEL1_CERT  "/opt/share/cert-svc/tests/orig_c/data/ocsp/ocsp_level1.crt"
#define CERT_FILE_REAL_LEVEL2_CA    "/opt/share/cert-svc/tests/orig_c/data/ocsp/ocsp_level2.crt"
#define CERT_FILE_REAL_ROOT_CA      "/opt/share/cert-svc/tests/orig_c/data/ocsp/ocsp_rootca.crt"

/*
 * author:      ---
 * test:        ocsp success:AIA information
 * description: Test for the ocsp success case using certificate's AIA information
 * expect:      *.pem should load with no error.
 */
int ocsp_success_with_aia() {
    int ret = CERT_SVC_ERR_NO_ERROR;
	CERT_CONTEXT* ctx = cert_svc_cert_context_init();

	// load certificate to context
	ret = cert_svc_load_file_to_context(ctx, CERT_FILE_SIGNER_AIA);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("....fail..cert_svc_push_file_to_context. ret=%d\n", ret); fflush(stderr);
		goto err;
	}

	// check ocsp
	ret = cert_svc_check_ocsp_status(ctx, NULL);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("....fail..cert_svc_check_ocsp_status. ret=%d\n", ret); fflush(stderr);
		goto err;
	}

err:
    cert_svc_cert_context_final(ctx);
    return ret;
}


/*
 * author:      ---
 * test:        ocsp success:no AIA information
 * description: Test for the ocsp success case using privided OCSP url
 * expect:      *.der file should load with no error.
 */
int ocsp_success_with_no_aia()
{
    int ret = CERT_SVC_ERR_NO_ERROR;
    char *uri = "http://127.0.0.1:8888";
	CERT_CONTEXT* ctx = cert_svc_cert_context_init();

	// load certificate to context
	ret = cert_svc_load_file_to_context(ctx, CERT_FILE_SIGNER_NOAIA);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("....fail..cert_svc_push_file_to_context. ret=%d\n", ret); fflush(stderr);
		goto err;
	}

	// check ocsp
	ret = cert_svc_check_ocsp_status(ctx, uri);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("....fail..cert_svc_check_ocsp_status. ret=%d\n", ret); fflush(stderr);
		goto err;
	}

err:
    cert_svc_cert_context_final(ctx);
    return ret;
}

/*
 * author:      ---
 * test:        ocsp fail: revokation.
 * description: Test for the ocsp fail case due to the revokation
 * expect:      *.pom file should not load and return error.
 */
int ocsp_fail_revokation()
{
    int ret = CERT_SVC_ERR_NO_ERROR;
    char *uri = "http://127.0.0.1:8888";
	CERT_CONTEXT* ctx = cert_svc_cert_context_init();

	// load certificate to context
	ret = cert_svc_load_file_to_context(ctx, CERT_FILE_SIGNER_REVOKED);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("....fail..cert_svc_push_file_to_context. ret=%d\n", ret); fflush(stderr);
		goto err;
	}

	// check ocsp
	ret = cert_svc_check_ocsp_status(ctx, uri);
    if(ret != CERT_SVC_ERR_OCSP_REVOKED) {
   		printf("....fail..CERT_SVC_ERR_OCSP_REVOKED Error expected. ret=%d\n", ret); fflush(stderr);
   		goto err;
    }

    ret = 0;
err:
	cert_svc_cert_context_final(ctx);
    return ret;
}


/*
 * author:      ---
 * test:        No URI
 * description: Test for the ocsp fail case due to no OCSP URL and AIA Information
 * expect:      .
 */
int ocsp_fail_no_uri()
{
    int ret = CERT_SVC_ERR_NO_ERROR;
	CERT_CONTEXT* ctx = cert_svc_cert_context_init();

	// load certificate to context
	ret = cert_svc_load_file_to_context(ctx, CERT_FILE_SIGNER_NOAIA);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("....fail..cert_svc_push_file_to_context. ret=%d\n", ret); fflush(stderr);
		goto err;
	}

	// check ocsp
	ret = cert_svc_check_ocsp_status(ctx, NULL);
    if(ret != CERT_SVC_ERR_OCSP_NO_SUPPORT) {
   		printf("....fail..CERT_SVC_ERR_OCSP_NO_SUPPORT Error expected. ret=%d\n", ret); fflush(stderr);
   		goto err;
    }
    ret = 0;
err:
  	cert_svc_cert_context_final(ctx);
    return ret;
}

/*
 * author:      ---
 * test:        Invalid URI
 * description: Test for the ocsp fail case due to Invalid OCSP URL
 * expect:      .
 */
int ocsp_fail_no_network()
{
    int ret = CERT_SVC_ERR_NO_ERROR;
    char *uri = "http://127.0.0.1:7171";
	CERT_CONTEXT* ctx = cert_svc_cert_context_init();

	// load certificate to context
	ret = cert_svc_load_file_to_context(ctx, CERT_FILE_SIGNER_NOAIA);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("....fail..cert_svc_push_file_to_context. ret=%d\n", ret); fflush(stderr);
		goto err;
	}

	// check ocsp
	ret = cert_svc_check_ocsp_status(ctx, uri);
    if(ret != CERT_SVC_ERR_OCSP_NETWORK_FAILED) {
   		printf("....fail..CERT_SVC_ERR_OCSP_NETWORK_FAILED Error expected. ret=%d\n", ret); fflush(stderr);
   		goto err;
    }
    ret = 0;
err:
  	cert_svc_cert_context_final(ctx);
    return ret;
}

/*
 * author:      ---
 * test:        Invalid Cert Chain
 * description: Test for the ocsp fail case due to Invalid  Cert Chain
 * expect:      .
 */
int ocsp_fail_invalid_cert_chain()
{
    int ret = CERT_SVC_ERR_NO_ERROR;
	char *url = NULL;
	CERT_CONTEXT* ctx = cert_svc_cert_context_init();

	// load certificate to context
	ret = cert_svc_load_file_to_context(ctx, CERT_FILE_NO_ROOT_CERT);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("....fail..cert_svc_push_file_to_context. ret=%d\n", ret); fflush(stderr);
		goto err;
	}

	// check ocsp
	ret = cert_svc_check_ocsp_status(ctx, NULL);
    if(ret != CERT_SVC_ERR_NO_ROOT_CERT) {
   		printf("....fail..CERT_SVC_ERR_NO_ROOT_CERT Error expected. ret=%d\n", ret); fflush(stderr);
   		goto err;
    }
    ret = 0;
err:
  	cert_svc_cert_context_final(ctx);
    return ret;
}

/*
 * author:      ---
 * test:        Null Certificate
 * description: Test for the ocsp fail case due to Null Certificate
 * expect:      .
 */
int ocsp_fail_null_cert()
{
    int ret = CERT_SVC_ERR_NO_ERROR;
    char *uri = "http://127.0.0.1:8888";
	CERT_CONTEXT* ctx = cert_svc_cert_context_init();

	// don't load certificate to context

	// check ocsp
	ret = cert_svc_check_ocsp_status(ctx, uri);
    if(ret != CERT_SVC_ERR_INVALID_PARAMETER) {
   		printf("....fail..CERT_SVC_ERR_INVALID_PARAMETER Error expected. ret=%d\n", ret); fflush(stderr);
   		goto err;
    }
    ret = 0;
err:
  	cert_svc_cert_context_final(ctx);
    return ret;
}

/*
 * author:      ---
 * test:        OCSP test.
 * description: Testing OCSP for certificate list.
 * expect:      OCSP should return success.
 */
int ocsp_success_real_cert()
{

    int ret = CERT_SVC_ERR_NO_ERROR;
	char *url = NULL;
	CERT_CONTEXT* ctx = cert_svc_cert_context_init();

	// load certificate to context
	ret = cert_svc_load_file_to_context(ctx, CERT_FILE_REAL_LEVEL1_CERT);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("....fail..cert_svc_push_file_to_context. file=%s, ret=%d\n", CERT_FILE_REAL_LEVEL1_CERT, ret); fflush(stderr);
		goto err;
	}

	ret = cert_svc_push_file_into_context(ctx, CERT_FILE_REAL_LEVEL2_CA);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("....fail..cert_svc_push_file_to_context. file=%s, ret=%d\n", CERT_FILE_REAL_LEVEL2_CA, ret); fflush(stderr);
		goto err;
	}

//	ret = cert_svc_push_file_into_context(ctx, CERT_FILE_REAL_ROOT_CA);
//	if(ret != CERT_SVC_ERR_NO_ERROR) {
//		printf("....fail..cert_svc_push_file_to_context. file=%s, ret=%d\n", CERT_FILE_REAL_ROOT_CA, ret); fflush(stderr);
//		goto err;
//	}

	// check ocsp
	ret = cert_svc_check_ocsp_status(ctx, NULL);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("....fail..cert_svc_check_ocsp_status. ret=%d\n", ret); fflush(stderr);
		goto err;
	}

err:
    cert_svc_cert_context_final(ctx);
    return ret;
}


typedef struct {
    unsigned long size,resident,share,text,lib,data,dt;
} statm_t;

void read_off_memory_status(statm_t  *result)
{
  unsigned long dummy;
  const char* statm_path = "/proc/self/statm";

//      /proc/[pid]/statm
//               Provides information about memory usage, measured in pages.
//            The columns are:
//                size          total program size(same as VmSize in /proc/[pid]/status)
//                resident    resident set size(same as VmRSS in /proc/[pid]/status)
//                share        shared pages (from shared mappings)
//                text          text (code)
//                lib             library (unused in Linux 2.6)
//                data         data + stack
//                dt             dirty pages (unused in Linux 2.6)


  FILE *f = fopen(statm_path,"r");
  if(!f){
    perror(statm_path);
    abort();
  }
  if(7 != fscanf(f,"%ld %ld %ld %ld %ld %ld %ld",
    &result->size,&result->resident,&result->share,&result->text,&result->lib,&result->data,&result->dt))
  {
    perror(statm_path);
    abort();
  }
  fclose(f);
}

/*
 * author:      ---
 * test:        Memory Leak Test
 * description: Test for Memory Leak
 * expect:      .
 */
int ocsp_success_memory_leak()
{
    int ret = CERT_SVC_ERR_NO_ERROR;
    statm_t memStatus;
    cert_svc_linked_list* sorted = NULL;
    int i;

    for(i=0; i<100; i++ ){
    	ocsp_success_with_aia();
    	ocsp_success_with_no_aia();
    	ocsp_fail_revokation();
    	ocsp_fail_no_uri();
    	ocsp_fail_no_network();
    	ocsp_fail_invalid_cert_chain();
    	ocsp_fail_null_cert();
        read_off_memory_status(&memStatus);
        printf("loop %d th : size=%d, resident=%d, share=%d, text=%d, lib=%d, data=%d, dt=%d\n", i,
        			memStatus.size, memStatus.resident, memStatus.share, memStatus.text,
        			memStatus.lib, memStatus.data, memStatus.dt);
    }
}

void run_test(int (*function)(), const char *function_name) {
	int ret = 0;

	printf("\n-- %s start\n", function_name);
	ret = (*function)();
	printf("---- result : ");
	if(ret == 0) {
		printf("success\n");
	}else {
		printf("fail\n");
	}
}

int test_ocsp(){
	int ret;
	printf("\n[test_ocsp started]\n");

	system("cert-svc-tests-start-ocsp-server.sh");
	sleep(1);

	run_test(&ocsp_success_with_aia, "ocsp_success_with_aia");
	run_test(&ocsp_success_with_no_aia, "ocsp_success_with_no_aia");
	run_test(&ocsp_fail_revokation, "ocsp_fail_revokation");
	run_test(&ocsp_fail_no_uri, "ocsp_fail_no_uri");
	run_test(&ocsp_fail_no_network, "ocsp_fail_no_network");
	run_test(&ocsp_fail_invalid_cert_chain, "ocsp_fail_invalid_cert_chain");
	run_test(&ocsp_fail_null_cert, "ocsp_fail_null_cert");
	run_test(&ocsp_success_real_cert, "ocsp_success_real_cert");
//	run_test(&ocsp_success_memory_leak, "ocsp_success_memory_leak");

	printf("\n");
	system("cert-svc-tests-kill-ocsp-server.sh");

	printf("\n[test_ocsp finished]\n");
	return ret;
}

#endif
