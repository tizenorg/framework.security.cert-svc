#include <stdio.h>
#include <unistd.h>

#include "cert-service.h"

#define	RELATIVE_PATH	"./data/Broot.der"
#define ABSOLUTE_PATH	"./data/Broot.der"	// for target

int tcase_1_success()
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	// delete 'Broot.der' from '.../code-signing/java/operator'
	ret = cert_svc_delete_certificate_from_store("Broot.der", "code-signing_java_operator");
	if(ret == CERT_SVC_ERR_NO_ERROR) {
		if((access("/opt/share/cert-svc/certs/code-signing/java/operator/Broot.der", F_OK)) != 0)
			return 0;
		else
			return -1;
	}
	else
		return -1;
}

int tcase_2_success()
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	// delete 'Broot.der' from '.../ssl'
	ret = cert_svc_delete_certificate_from_store("Broot.der", NULL);
	if(ret == CERT_SVC_ERR_NO_ERROR) {
		if((access("/opt/share/cert-svc/certs/ssl/Broot.der", F_OK)) != 0)
			return 0;
		else
			return -1;
	}
	else
		return -1;
}

int tcase_3_fail()
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	// delete NULL 
	ret = cert_svc_delete_certificate_from_store(NULL, "code-signing_java_operator");
	if(ret == CERT_SVC_ERR_INVALID_PARAMETER)
		return 0;
	else
		return -1;
}

int tcase_4_fail()
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	// delete 'Broot.der' from invalid directory
	ret = cert_svc_delete_certificate_from_store("Broot.der", "code-signing_debian");
	if(ret == CERT_SVC_ERR_FILE_IO)
		return 0;
	else
		return -1;
}

int main(void)
{
	int ret = -1;

	// store test files
	cert_svc_add_certificate_to_store(RELATIVE_PATH, "code-signing_java_operator");
	cert_svc_add_certificate_to_store(RELATIVE_PATH, NULL);

	// test case 1 : success
	ret = tcase_1_success();
	if(ret == 0)
		fprintf(stdout, "** Success to delete test 1 - testpath: code-signing **\n");
	else
		fprintf(stdout, "** Fail to delete test1 **\n");

	// test case 2 : success - no location (ssl)
	ret = tcase_2_success();
	if(ret == 0)
		fprintf(stdout, "** Success to delete test 2 - testpath: ssl **\n");
	else
		fprintf(stdout, "** Fail to delete test2 **\n");

	// test case 3 : fail - no filename
	ret = tcase_3_fail();
	if(ret == 0)
		fprintf(stdout, "** Success to delete test 3 - no filename **\n");
	else
		fprintf(stdout, "** Fail to delete test3 **\n");

	// test case 4 : fail - invalid dir name
	ret = tcase_4_fail();
	if(ret == 0)
		fprintf(stdout, "** Success to delete test 4 - invalid dir path  **\n");
	else
		fprintf(stdout, "** Fail to delete test4 **\n");

	return 0;
}
