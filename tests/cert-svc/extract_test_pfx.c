#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cert-service.h"

int main(int argc, char* argv[])
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	CERT_CONTEXT* ctx = NULL;
	cert_svc_cert_descriptor* certDesc = NULL;
	int i = 0, keyLen = 0;
	int extNum = 0, j = 0;
//	unsigned char* prikey = NULL;

	ctx = cert_svc_cert_context_init();

	if((ret = cert_svc_load_file_to_context(ctx, argv[1])) != CERT_SVC_ERR_NO_ERROR) {
		printf("file: [%s]\n", argv[1]);
		printf("*** Fail to load file, ret: [%d]\n", ret);
	}
//	if((ret = cert_svc_load_PFX_file_to_context(ctx, &prikey, argv[1], "test")) != CERT_SVC_ERR_NO_ERROR) {
//		printf("file: [%s]\n", argv[1]);
//		printf("*** Fail to load file, ret: [%d]\n", ret);
//	}

	if((ret = cert_svc_extract_certificate_data(ctx)) != CERT_SVC_ERR_NO_ERROR)
		printf("*** Fail to extract certificate, ret: [%d]\n", ret);

//	printf("private key: [%s]\n", prikey);

	certDesc = ctx->certDesc;

	printf("type: [%s]\n", certDesc->type);
	printf("version: [%d]\n", certDesc->info.version);
	printf("serial number: [%d]\n", certDesc->info.serialNumber);
	printf("signature algorithm: [%s]\n", certDesc->info.sigAlgo);
	printf("issuer: [%s]\n", certDesc->info.issuerStr);
	printf("    country name: [%s]\n", certDesc->info.issuer.countryName);
	printf("    state or province name: [%s]\n", certDesc->info.issuer.stateOrProvinceName);
	printf("    locality name: [%s]\n", certDesc->info.issuer.localityName);
	printf("    organization name: [%s]\n", certDesc->info.issuer.organizationName);
	printf("    organization unit name: [%s]\n", certDesc->info.issuer.organizationUnitName);
	printf("    common name: [%s]\n", certDesc->info.issuer.commonName);
	printf("    email address: [%s]\n", certDesc->info.issuer.emailAddress);
	printf("validity:\n");
	printf("    not before: [%d].[%d].[%d]/[%d]:[%d]:[%d]\n", certDesc->info.validPeriod.firstYear,
			certDesc->info.validPeriod.firstMonth,
			certDesc->info.validPeriod.firstDay,
			certDesc->info.validPeriod.firstHour,
			certDesc->info.validPeriod.firstMinute,
			certDesc->info.validPeriod.firstSecond);
	printf("    not after:  [%d].[%d].[%d]/[%d]:[%d]:[%d]\n", certDesc->info.validPeriod.secondYear,
			certDesc->info.validPeriod.secondMonth,
			certDesc->info.validPeriod.secondDay,
			certDesc->info.validPeriod.secondHour,
			certDesc->info.validPeriod.secondMinute,
			certDesc->info.validPeriod.secondSecond);
	printf("subject: [%s]\n", certDesc->info.subjectStr);
	printf("    country name: [%s]\n", certDesc->info.subject.countryName);
	printf("    state or province name: [%s]\n", certDesc->info.subject.stateOrProvinceName);
	printf("    locality name: [%s]\n", certDesc->info.subject.localityName);
	printf("    organization name: [%s]\n", certDesc->info.subject.organizationName);
	printf("    organization unit name: [%s]\n", certDesc->info.subject.organizationUnitName);
	printf("    common name: [%s]\n", certDesc->info.subject.commonName);
	printf("    email address: [%s]\n", certDesc->info.subject.emailAddress);
//	printf("public key:\n");
//	keyLen = certDesc->info.pubKeyLen;
//	printf("    algorithm: [%s]\n", certDesc->info.pubKeyAlgo);
//	printf("    key:\n");
//	for(i = 0; i < keyLen; i++) {
//		printf("%02X", certDesc->info.pubKey[i]);
//		if(i < (keyLen - 1))
//			printf(":");
//		if(((i+1) % 10) == 0)
//			printf("\n");
//	}
//	printf("\n");
//	printf("issuer UID: [%s]\n", certDesc->info.issuerUID);
//	printf("subject UID: [%s]\n", certDesc->info.subjectUID);
//
//	printf("extensions:\n");
//	extNum = certDesc->ext.numOfFields;
//	for(i = 0; i < extNum; i++) {
//		printf("    field : [%s]\n", certDesc->ext.fields[i].name);
//		printf("    data  : ");
//		for(j = 0; j < certDesc->ext.fields[i].datasize; j++) {
//			printf("%02X", certDesc->ext.fields[i].data[j]);
//			if(j < (certDesc->ext.fields[i].datasize - 1))
//				printf(":");
//		}
//		printf("\n");
//	}
//
//	printf("signature:\n");
//	printf("    signature algorithm: [%s]\n", certDesc->signatureAlgo);
//	printf("    signature data:\n");
//	for(i = 0; i < certDesc->signatureLen; i++) {
//		printf("%02X", certDesc->signatureData[i]);
//		if(i < (certDesc->signatureLen - 1))
//			printf(":");
//		if(((i+1) % 10) == 0)
//			printf("\n");
//	}
//	printf("\n");
			
	if((ret = cert_svc_cert_context_final(ctx)) != CERT_SVC_ERR_NO_ERROR)
		printf("*** Fail to finalize context, ret: [%d]\n", ret);
	
	return ret;
}
