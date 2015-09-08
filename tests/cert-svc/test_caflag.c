/*
 * certification service
 *
 * Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Contact: Dongsun Lee <ds73.lee@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <test_suite.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <cert-service.h>
#include <cert-service-util.h>

#define	CERT_FILE_ROOT_CA				"/opt/share/cert-svc/tests/orig_c/data/caflag/root_ca.der"
#define	CERT_FILE_SECOND_CA				"/opt/share/cert-svc/tests/orig_c/data/caflag/second_ca.der"
#define	CERT_FILE_SIGNER_AIA			"/opt/share/cert-svc/tests/orig_c/data/caflag/aia_signer.der"
#define	CERT_FILE_SIGNER_REVOKED		"/opt/share/cert-svc/tests/orig_c/data/caflag/rev_signer.der"
#define	CERT_FILE_SIGNER_NOAIA			"/opt/share/cert-svc/tests/orig_c/data/caflag/noaia_signer.der"
#define	CERT_FILE_ROOT_CA_V1			"/opt/share/cert-svc/tests/orig_c/data/caflag/root_ca_v1.der"
#define	CERT_FILE_SIGNER_V1				"/opt/share/cert-svc/tests/orig_c/data/caflag/v1_signer.der"


int test_verify_certificate_succ_caflag_cert() {
	int validity;
    int ret = CERT_SVC_ERR_NO_ERROR;
	CERT_CONTEXT* ctx = cert_svc_cert_context_init();

	// load certificate to context
	ret = cert_svc_load_file_to_context(ctx, CERT_FILE_SIGNER_AIA);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("....fail..cert_svc_load_file_to_context. ret=%d\n", ret); fflush(stderr);
		goto err;
	}

	ret = cert_svc_push_file_into_context(ctx, CERT_FILE_SECOND_CA);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("....fail..cert_svc_push_file_to_context. ret=%d\n", ret); fflush(stderr);
		goto err;
	}

	ret = cert_svc_verify_certificate(ctx, &validity);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("....fail..cert_svc_verify_certificate. ret=%d\n", ret); fflush(stderr);
		goto err;
	}

	if(validity != 1) {
		printf("....fail..cert_svc_verify_certificate. validity=%d\n", validity); fflush(stderr);
		ret = -1;
		goto err;
	}

err:
    cert_svc_cert_context_final(ctx);
	return ret;
}

int test_verify_certificate_succ_nocaflag_cert() {
	int validity;
    int ret = CERT_SVC_ERR_NO_ERROR;
	CERT_CONTEXT* ctx = cert_svc_cert_context_init();

	// load certificate to context
	ret = cert_svc_load_file_to_context(ctx, CERT_FILE_SIGNER_V1);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("....fail..cert_svc_load_file_to_context. ret=%d\n", ret); fflush(stderr);
		goto err;
	}

	ret = cert_svc_verify_certificate(ctx, &validity);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("....fail..cert_svc_verify_certificate. ret=%d\n", ret); fflush(stderr);
		goto err;
	}

	if(validity != 1) {
		printf("....fail..cert_svc_verify_certificate. validity=%d\n", validity); fflush(stderr);
		ret = -1;
		goto err;
	}

err:
    cert_svc_cert_context_final(ctx);
	return ret;
}

int test_verify_certificate_with_caflag_succ() {
	int validity;
    int ret = CERT_SVC_ERR_NO_ERROR;
	CERT_CONTEXT* ctx = cert_svc_cert_context_init();

	// load certificate to context
	ret = cert_svc_load_file_to_context(ctx, CERT_FILE_SIGNER_AIA);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("....fail..cert_svc_load_file_to_context. ret=%d\n", ret); fflush(stderr);
		goto err;
	}

	ret = cert_svc_push_file_into_context(ctx, CERT_FILE_SECOND_CA);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("....fail..cert_svc_push_file_to_context. ret=%d\n", ret); fflush(stderr);
		goto err;
	}

	ret = cert_svc_verify_certificate_with_caflag(ctx, &validity);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("....fail..cert_svc_verify_certificate. ret=%d\n", ret); fflush(stderr);
		goto err;
	}

	if(validity != 1) {
		printf("....fail..cert_svc_verify_certificate. validity=%d\n", validity); fflush(stderr);
		ret = -1;
		goto err;
	}

err:
    cert_svc_cert_context_final(ctx);
	return ret;
}


int test_verify_certificate_with_caflag_fail() {
	int validity;
    int ret = CERT_SVC_ERR_NO_ERROR;
	CERT_CONTEXT* ctx = cert_svc_cert_context_init();

	// load certificate to context
	ret = cert_svc_load_file_to_context(ctx, CERT_FILE_SIGNER_V1);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("....fail..cert_svc_load_file_to_context. ret=%d\n", ret); fflush(stderr);
		goto err;
	}

	ret = cert_svc_verify_certificate_with_caflag(ctx, &validity);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("....fail..cert_svc_verify_certificate. ret=%d\n", ret); fflush(stderr);
		goto err;
	}

	if(validity == 1) {
		printf("....fail..cert_svc_verify_certificate. validity=%d\n", validity); fflush(stderr);
		ret = -1;
		goto err;
	}

err:
    cert_svc_cert_context_final(ctx);
	return ret;
}


int test_caflag(){
	int ret;
	printf("\n[test_caflag started]\n");

	printf("\n-- test_verify_certificate_succ_caflag_cert start\n");
	ret = test_verify_certificate_succ_caflag_cert();
	printf("---- result : ");
	if(ret == 0) {
		printf("success\n");
	}else {
		printf("fail\n");
	}

	printf("\n-- test_verify_certificate_succ_nocaflag_cert start\n");
	ret = test_verify_certificate_succ_nocaflag_cert();
	printf("---- result : ");
	if(ret == 0) {
		printf("success\n");
	}else {
		printf("fail\n");
	}

	printf("\n-- test_verify_certificate_with_caflag_succ start\n");
	ret = test_verify_certificate_with_caflag_succ();
	printf("---- result : ");
	if(ret == 0) {
		printf("success\n");
	}else {
		printf("fail\n");
	}

	printf("\n-- test_verify_certificate_with_caflag_fail start\n");
	ret = test_verify_certificate_with_caflag_fail();
	printf("---- result : ");
	if(ret == 0) {
		printf("success\n");
	}else {
		printf("fail\n");
	}

	return ret;
}
