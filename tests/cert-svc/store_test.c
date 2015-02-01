#include <stdio.h>
#include <unistd.h>

#include "cert-service.h"

#define RELATIVE_PATH	"./data/Broot.der"
#define ABSOLUTE_PATH	"./data/Broot.der"

int tcase_1_success()
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	// store relative path
	ret = cert_svc_add_certificate_to_store(RELATIVE_PATH, "code-signing_java_thirdparty");
	if(ret == CERT_SVC_ERR_NO_ERROR) {
		if((access("/opt/share/cert-svc/certs/code-signing/java/thirdparty/Broot.der", F_OK)) != 0)	// fail
			return -1;
		else
			return 0;
	}
	else
		return -1;

	// store absolute path - only be in target
}

int tcase_2_success()
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	// store into default path
	ret = cert_svc_add_certificate_to_store(RELATIVE_PATH, NULL);
	if(ret == CERT_SVC_ERR_NO_ERROR) {
		if((access("/opt/share/cert-svc/certs/ssl/Broot.der", F_OK)) != 0)	// fail
			return -1;
		else
			return 0;
	}
	else
		return -1;
}

int tcase_3_fail()
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	// store NULL
	ret = cert_svc_add_certificate_to_store(NULL, "code-signing_wac");
	if(ret == CERT_SVC_ERR_INVALID_PARAMETER)
		return 0;
	else
		return -1;
}

int tcase_4_fail()
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	// store into invalid directory
	ret = cert_svc_add_certificate_to_store(RELATIVE_PATH, "code-signing_debian");
	if(ret == CERT_SVC_ERR_FILE_IO)
		return 0;
	else
		return -1;
}

int finalize_test()
{
	// delete files which be stored during testing
	if((unlink("/opt/share/cert-svc/certs/code-signing/java/thirdparty/Broot.der")) != 0)	// fail
		return -1;
	if((unlink("/opt/share/cert-svc/certs/ssl/Broot.der")) != 0)	// fail
		return -1;

	return 0;
}

int main(void)
{
	int ret = -1;

	// test case 1 : success
	ret = tcase_1_success();
	if(ret == 0)
		fprintf(stdout, "** Success to store test 1 - testpath: code_signing **\n");
	else
		fprintf(stdout, "** Fail to store test 1 **\n");

	// test case 2 : success - no location (ssl)
	ret = tcase_2_success();
	if(ret == 0)
		fprintf(stdout, "** Success to store test 2 - testpath: ssl **\n");
	else 
		fprintf(stdout, "** Fail to store test 2 **\n");

	// test case 3 : fail - no filename
	ret = tcase_3_fail();
	if(ret == 0)
		fprintf(stdout, "** Success to store test 3 - no filename **\n");
	else 
		fprintf(stdout, "** Fail to store test 3 **\n");

	// test case 4 : fail - invalid dir name
	ret = tcase_4_fail();
	if(ret == 0)
		fprintf(stdout, "** Success to store test 4 - invalid dir path **\n");
	else 
		fprintf(stdout, "** Fail to store test 4 **\n");

	// test finalize
	ret = finalize_test();
	if(ret == 0)
		fprintf(stdout, "** Finalize store test **\n");
	else 
		fprintf(stdout, "** Fail to finalize store test, ret: [%d] **\n", ret);

	return 0;
}
