#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cert-service.h"

#define CERT_PATH	"./data/signing/chain1.crt"
#define MSG_PATH	"./data/signing/msg"
//#define SIG_PATH	"./data/signing/msg.sig"
#define SIG_PATH	"./data/signing/msg.sig.enc"

int main(int argc, char* argv[])
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	int validity = 0;
	CERT_CONTEXT* ctx = NULL;
	unsigned char* msg = NULL;
	int msgLen = 0;
	unsigned char* sig = NULL;
	unsigned char* tmpSig = NULL;
	int sigLen = 0;
	FILE* fp_msg = NULL;
	FILE* fp_sig = NULL;
	int i = 0, j = 0;

	ctx = cert_svc_cert_context_init();

	// load certificate
	if((ret = cert_svc_load_file_to_context(ctx, CERT_PATH)) != CERT_SVC_ERR_NO_ERROR) {
		printf("Fail to load file to buffer, [%s]\n", CERT_PATH);
		goto err;
	}

	// load message
	if(!(fp_msg = fopen(MSG_PATH, "rb"))) {
		printf("Fail to open file, [%s]\n", MSG_PATH);
		goto err;
	}
	fseek(fp_msg, 0L, SEEK_END);
	msgLen = ftell(fp_msg);
	fseek(fp_msg, 0L, SEEK_SET);

	msg = (unsigned char*)malloc(sizeof(unsigned char) * (msgLen + 1));
	memset(msg, 0x00, (msgLen + 1));
	fread(msg, sizeof(unsigned char), msgLen, fp_msg);

	// load signature
	if(!(fp_sig = fopen(SIG_PATH, "rb"))) {
		printf("Fail to open file, [%s]\n", SIG_PATH);
		goto err;
	}
	fseek(fp_sig, 0L, SEEK_END);
	sigLen = ftell(fp_sig);
	fseek(fp_sig, 0L, SEEK_SET);

	sig = (unsigned char*)malloc(sizeof(unsigned char) * (sigLen + 1));
	tmpSig = (unsigned char*)malloc(sizeof(unsigned char) * (sigLen + 1));
	memset(sig, 0x00, (sigLen + 1));
	memset(tmpSig, 0x00, (sigLen + 1));

	fread(sig, sizeof(unsigned char), sigLen, fp_sig);
	for(i = 0; i < sigLen; i++) {
		if(sig[i] != '\n') {
			tmpSig[j] = sig[i];
			j++;
		}
	}

	// function call
//	if((ret = cert_svc_verify_signature(ctx, msg, sig, sigLen, "SHA1", &validity)) != CERT_SVC_ERR_NO_ERROR) {
	if((ret = cert_svc_verify_signature(ctx, msg, msgLen, tmpSig, NULL, &validity)) != CERT_SVC_ERR_NO_ERROR) {
		printf("Fail to verify signature.\n");
		goto err;
	}
	printf("[RESULT] ret: [%d]\n", validity);

err:
	if(fp_msg != NULL) fclose(fp_msg);
	if(fp_sig != NULL) fclose(fp_sig);
	if(msg != NULL) free(msg);
	if(sig != NULL) free(sig);
	if(tmpSig != NULL) free(tmpSig);
	cert_svc_cert_context_final(ctx);

	return 0;
}
