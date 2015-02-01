#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cert-service.h"

#define TARGET_CERT	"./data/cert_chain/server.crt"
#define CHAIN1_CERT	"./data/cert_chain/chain1.crt"
#define CHAIN2_CERT	"./data/cert_chain/chain2.crt"
#define CHAIN3_CERT	"./data/cert_chain/chain3.crt"
#define CHAIN4_CERT	"./data/cert_chain/chain4.crt"
#define CHAIN5_CERT	"./data/cert_chain/chain5.crt"

int main()
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	int validity = 0;
	CERT_CONTEXT* ctx = cert_svc_cert_context_init();

	// load certificate to context
//	if((ret = cert_svc_load_file_to_context(ctx, TARGET_CERT)) != CERT_SVC_ERR_NO_ERROR) {
	if((ret = cert_svc_load_file_to_context(ctx, CHAIN1_CERT)) != CERT_SVC_ERR_NO_ERROR) {
		printf("ERR!! ret: [%d]\n", ret);
		goto err;
	}

	// push certificates to context
//	if((ret = cert_svc_push_file_into_context(ctx, CHAIN1_CERT)) != CERT_SVC_ERR_NO_ERROR) {
//		printf("ERR!! ret: [%d]\n", ret);
//		goto err;
//	}
//	if((ret = cert_svc_push_file_into_context(ctx, CHAIN2_CERT)) != CERT_SVC_ERR_NO_ERROR) {
//		printf("ERR!! ret: [%d]\n", ret);
//		goto err;
//	}
//	if((ret = cert_svc_push_file_into_context(ctx, CHAIN5_CERT)) != CERT_SVC_ERR_NO_ERROR) {
//		printf("ERR!! ret: [%d]\n", ret);
//		goto err;
//	}
//	if((ret = cert_svc_push_file_into_context(ctx, CHAIN4_CERT)) != CERT_SVC_ERR_NO_ERROR) {
//		printf("ERR!! ret: [%d]\n", ret);
//		goto err;
//	}
//	if((ret = cert_svc_push_file_into_context(ctx, CHAIN3_CERT)) != CERT_SVC_ERR_NO_ERROR) {
//		printf("ERR!! ret: [%d]\n", ret);
//		goto err;
//	}
//
//	// check linked list
//	if(ctx->certLink == NULL) {
//		printf("FAIL!!\n");
//		goto err;
//	}

	// verify
	ret = cert_svc_verify_certificate(ctx, &validity);
	if(ret != CERT_SVC_ERR_NO_ERROR)
		printf("ret: [%d]\n", ret);

	printf("[RESULT] validity: [%d]\n", validity);
	printf("[RESULT] root CA path: [%s]\n", ctx->fileNames->filename);

err:
	cert_svc_cert_context_final(ctx);
	return 0;
}
