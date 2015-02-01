#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cert-service.h"

#define	DER_CERT	"./data/Broot.pem"
#define PEM_CERT	"./data/Broot.der"
#define PFX_CERT	"./data/pfx/temp/server.pfx"
#define INVALID_CERT	"./data/invalidCert.der"

int tcase_1_success()
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	CERT_CONTEXT* ctx = NULL;

	// initialize cert context
	ctx = cert_svc_cert_context_init();

	// load certificate file to buffer
	if((ret = cert_svc_load_file_to_context(ctx, DER_CERT)) != CERT_SVC_ERR_NO_ERROR)
		goto err;

	// extract certificate data
	if((ret = cert_svc_extract_certificate_data(ctx)) != CERT_SVC_ERR_NO_ERROR)
		goto err;

err:
	// finalize cert context
	cert_svc_cert_context_final(ctx);
	return ret;
}

int tcase_2_success()
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	CERT_CONTEXT* ctx = NULL;

	// initialize cert context
	ctx = cert_svc_cert_context_init();

	// load certificate file to buffer
	if((ret = cert_svc_load_file_to_context(ctx, PEM_CERT)) != CERT_SVC_ERR_NO_ERROR)
		goto err;

	// extract certificate data
	if((ret = cert_svc_extract_certificate_data(ctx)) != CERT_SVC_ERR_NO_ERROR)
		goto err;

err:
	// finalize cert context
	cert_svc_cert_context_final(ctx);
	return ret;
}

int tcase_3_success()
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	CERT_CONTEXT* ctx = NULL;
	unsigned char* prikey = NULL;
	char* pass = "test\0";

	// initialize cert context
	ctx = cert_svc_cert_context_init();

	// load certificate file to buffer
	if((ret = cert_svc_load_PFX_file_to_context(ctx, &prikey, PFX_CERT, pass)) != CERT_SVC_ERR_NO_ERROR)
		goto err;
	printf(" ****** prikey: [%s]\n", prikey);

	// extract certificate data
	if((ret = cert_svc_extract_certificate_data(ctx)) != CERT_SVC_ERR_NO_ERROR)
		goto err;

err:
	// finalize cert context
	cert_svc_cert_context_final(ctx);
	if(prikey != NULL)
		free(prikey);
	return ret;
}

int tcase_4_fail()
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	CERT_CONTEXT* ctx = NULL;

	// initialize cert context
	ctx = cert_svc_cert_context_init();

	// extract certificate data
	if((ret = cert_svc_extract_certificate_data(ctx)) != CERT_SVC_ERR_INVALID_PARAMETER)
		goto err;
	ret = CERT_SVC_ERR_NO_ERROR;

err:
	// finalize cert context
	cert_svc_cert_context_final(ctx);
	return ret;
}

int tcase_5_fail()
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	CERT_CONTEXT* ctx = NULL;

	// initialize cert context
	ctx = cert_svc_cert_context_init();

	// load certificate file to buffer
	if((ret = cert_svc_load_file_to_context(ctx, INVALID_CERT)) != CERT_SVC_ERR_NO_ERROR)
		goto err;

	// extract certificate data
	if((ret = cert_svc_extract_certificate_data(ctx)) != CERT_SVC_ERR_INVALID_CERTIFICATE)
		goto err;
	ret = CERT_SVC_ERR_NO_ERROR;

err:
	// finalize cert context
	cert_svc_cert_context_final(ctx);
	return ret;
}

int main(int argc, char* argv[])
{
	int ret = -1;

	// store test certificate
	cert_svc_add_certificate_to_store(DER_CERT, NULL);
	cert_svc_add_certificate_to_store(PEM_CERT, NULL);
	cert_svc_add_certificate_to_store(PFX_CERT, NULL);
	
	// extract test - success: PEM
	ret = tcase_1_success();
	if(ret == 0)
		fprintf(stdout, "** Success to extract certificate: DER type **\n");
	else
		fprintf(stdout, "** Fail to extract certificate: DER type **\n");

	// extract test - success: DER
	ret = tcase_2_success();
	if(ret == 0)
		fprintf(stdout, "** Success to extract certificate: PEM type **\n");
	else
		fprintf(stdout, "** Fail to extract certificate: PEM type **\n");

	// extract test - success: PFX
	ret = tcase_3_success();
	if(ret == 0)
		fprintf(stdout, "** Success to extract certificate: PFX type **\n");
	else
		fprintf(stdout, "** Fail to extract certificate: PFX type **\n");

	// extract test - fail: no file
	ret = tcase_4_fail();
	if(ret == 0)
		fprintf(stdout, "** Success to extract certificate: no certificate **\n");
	else
		fprintf(stdout, "** Fail to extract certificate: no certificate **\n");

	// extract test - fail: invalid certificate
	ret = tcase_5_fail();
	if(ret == 0)
		fprintf(stdout, "** Success to extract certificate: invalid certificate **\n");
	else
		fprintf(stdout, "** Fail to extract certificate: invalid certificate **\n");

	// delete test certificate
	cert_svc_delete_certificate_from_store("Broot.pem", NULL);
	cert_svc_delete_certificate_from_store("Broot.der", NULL);
	cert_svc_delete_certificate_from_store("server.pfx", NULL);

	return 0;
}
