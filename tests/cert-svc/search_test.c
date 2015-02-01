#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cert-service.h"

int main(int argc, char* argv[])
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	search_field fldNo = ISSUER_EMAILADDRESS;
	char* fldData = "EmailR";
	cert_svc_filename_list* start = NULL;
	CERT_CONTEXT* ctx = NULL;

	ctx = cert_svc_cert_context_init();

	ret = cert_svc_search_certificate(ctx, fldNo, fldData);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("[ERROR] error no: [%d]\n", ret);
		goto err;
	}
	else {
		start = ctx->fileNames;
		if(start == NULL) {
			printf("Cannot find any certificate.\n");
			goto err;
		}

		while(1) {
			printf("filename: [%s]\n", start->filename);
			if(start->next == NULL)
				break;
			start = start->next;
		}
	}

err:
	cert_svc_cert_context_final(ctx);
	return 0;
}
