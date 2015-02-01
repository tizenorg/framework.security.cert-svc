#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cert-service.h"

#define CERT_FILE	"./data/Broot.pem"
#define PFX_FILE	"./data/pfx/pfxtest.pfx"

int main()
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	CERT_CONTEXT* ctx = NULL;
	unsigned char* prikey = NULL;
	char* passp = NULL;

	// initialize
	ctx = cert_svc_cert_context_init();

	// file load
//	ret = cert_svc_load_file_to_context(ctx, CERT_FILE);
	ret = cert_svc_load_PFX_file_to_context(ctx, &prikey, PFX_FILE, passp);
	if(ret != CERT_SVC_ERR_NO_ERROR)
		printf("\n!!!! FILE LOAD ERROR !!!!\n");

	// extract
//	ret = cert_svc_extract_certificate_data(ctx);
//	if(ret != CERT_SVC_ERR_NO_ERROR)
//		printf("\n!!!! EXTRACT CERT ERROR !!!!\n");
	
	// finalize
	if(prikey != NULL)
		free(prikey);
	ret = cert_svc_cert_context_final(ctx);
	if(ret != CERT_SVC_ERR_NO_ERROR)
		printf("\n!!!! CONTEXT FINAL ERROR !!!!\n");

	return 0;
}
