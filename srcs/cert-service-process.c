/*
 * certification service
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Contact: Kidong Kim <kd0228.kim@samsung.com>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <error.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fts.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/ocsp.h>

#include "cert-service.h"
#include "cert-service-util.h"
#include "cert-service-debug.h"
#include "cert-service-process.h"

#define get_ASN1_INTEGER(x)	ASN1_INTEGER_get((x))
#define get_ASN1_OBJECT(x)	OBJ_nid2ln(OBJ_obj2nid((x)))
#define get_X509_NAME(x)	X509_NAME_oneline((x), NULL, 0)

struct verify_context {
	int depth;
};

typedef struct {
	char* unitName;
	char* address;
	int len;
} name_field;

int _check_certificate_author(cert_svc_mem_buff* first, cert_svc_mem_buff* second);
static unsigned char** __get_field_by_tag(unsigned char* str, int *tag_len, cert_svc_name_fld_data* fld)
{
	const struct {
		const char* name;
		int len;
		unsigned char **field;
	} tags[] = {
		{"C=", 2, &(fld->countryName)},
		{"ST=", 3, &(fld->stateOrProvinceName)},
		{"L=", 2, &(fld->localityName)},
		{"O=", 2, &(fld->organizationName)},
		{"OU=", 3, &(fld->organizationUnitName)},
		{"CN=", 3, &(fld->commonName)},
		{"emailAddress=", 13, &(fld->emailAddress)}
	};
	unsigned char **field = NULL;
	if (str[0] == '/') {
		int i = sizeof(tags) / sizeof(tags[0]) - 1;
		while (i >= 0 && strncmp((const char*)(str + 1), (const char*)(tags[i].name), tags[i].len)) {
			i--;
		}
		if (i >= 0) {
			*tag_len = tags[i].len + 1;
			field = tags[i].field;
		}
	}
	return field;
}

/*SURC k.astrakhant 2011.07.14 : this version can parse info string with any order of tags*/
int parse_name_fld_data(unsigned char* str, cert_svc_name_fld_data* fld)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	unsigned char **prev_field = NULL;
	int i = 0, l = 0;
    if (fld == NULL) {
        ret = CERT_SVC_ERR_INVALID_PARAMETER;
        return ret;
    }
	memset(fld, 0, sizeof(cert_svc_name_fld_data));
	while (str[i] != '\0') {
		int tag_len;
		unsigned char **field = __get_field_by_tag(str + i, &tag_len, fld);
		while (field == NULL && str[i] != '\0') {
			i++;
			field = __get_field_by_tag(str + i, &tag_len, fld);
		}
		if (prev_field != NULL) {
			*prev_field = (unsigned char*)strndup((const char*)(str + l), i - l);
		}
		if (field != NULL) {
			i += tag_len;
			l = i;
			prev_field = field;
		}
	}
//	SLOGD("! %s, %s, %s, %s, %s, %s, %s\n", fld->countryName, fld->stateOrProvinceName, fld->localityName, fld->organizationName, fld->organizationUnitName, fld->commonName, fld->emailAddress);
	return ret;
}

int _parse_name_fld_data(unsigned char* str, cert_svc_name_fld_data* fld)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	int i = 0, j = 0, last = -1;
	char* tmpAddr = NULL;
	name_field tmpFld[7] = {
		{"/C=", NULL, 0},
		{"/ST=", NULL, 0},
		{"/L=", NULL, 0},
		{"/O=", NULL, 0},
		{"/OU=", NULL, 0},
		{"/CN=", NULL, 0},
		{"/emailAddress=", NULL, 0}
	};

	for(i = 0; i < 7; i++) {
		if((tmpAddr = strstr((const char*)str, (const char*)(tmpFld[i].unitName))) != NULL)
			tmpFld[i].address = tmpAddr;
		else
			tmpFld[i].address = NULL;
	}

	for(i = 0; i < 6; i++) {
		if(tmpFld[i].address != NULL) {
			for(j = i + 1; j < 7; j++) {
				if(tmpFld[j].address != NULL) {
					last = j;
					tmpFld[i].len = (int)(tmpFld[j].address) - (int)(tmpFld[i].address) - strlen((const char*)(tmpFld[i].unitName));
					break;
				}
			}
		}
	}
	tmpFld[last].len = strlen((const char*)str) - ((int)(tmpFld[last].address) - (int)str) - strlen((const char*)(tmpFld[last].unitName));

	if(tmpFld[0].address != NULL) {
		(*fld).countryName = (unsigned char*)malloc(sizeof(unsigned char) * (tmpFld[0].len + 1));
		if ((*fld).countryName != NULL)
		{
			memset((*fld).countryName, 0x00, (tmpFld[0].len + 1));
			memcpy((*fld).countryName, (tmpFld[0].address + strlen((const char*)(tmpFld[0].unitName))), tmpFld[0].len);
		}
	}
	else
		(*fld).countryName = NULL;
	if(tmpFld[1].address != NULL) {
		(*fld).stateOrProvinceName = (unsigned char*)malloc(sizeof(unsigned char) * (tmpFld[1].len + 1));
		if ((*fld).stateOrProvinceName != NULL) {
			memset((*fld).stateOrProvinceName, 0x00, (tmpFld[1].len + 1));
			memcpy((*fld).stateOrProvinceName, (tmpFld[1].address + strlen((const char*)(tmpFld[1].unitName))), tmpFld[1].len);
		}
	}
	else
		(*fld).stateOrProvinceName = NULL;
	if(tmpFld[2].address != NULL) {
		(*fld).localityName = (unsigned char*)malloc(sizeof(unsigned char) * (tmpFld[2].len + 1));
		if ((*fld).localityName != NULL) {
			memset((*fld).localityName, 0x00, (tmpFld[2].len + 1));
			memcpy((*fld).localityName, (tmpFld[2].address + strlen((const char*)(tmpFld[2].unitName))), tmpFld[2].len);
		}
	}
	else
		(*fld).localityName = NULL;
	if(tmpFld[3].address != NULL) {
		(*fld).organizationName = (unsigned char*)malloc(sizeof(unsigned char) * (tmpFld[3].len + 1));
		if ((*fld).organizationName != NULL) {
			memset((*fld).organizationName, 0x00, (tmpFld[3].len + 1));
			memcpy((*fld).organizationName, (tmpFld[3].address + strlen((const char*)(tmpFld[3].unitName))), tmpFld[3].len);
		}
	}
	else
		(*fld).organizationName = NULL;
	if(tmpFld[4].address != NULL) {
		(*fld).organizationUnitName = (unsigned char*)malloc(sizeof(unsigned char) * (tmpFld[4].len + 1));
		if ((*fld).organizationUnitName != NULL) {
			memset((*fld).organizationUnitName, 0x00, (tmpFld[4].len + 1));
			memcpy((*fld).organizationUnitName, (tmpFld[4].address + strlen((const char*)(tmpFld[4].unitName))), tmpFld[4].len);
		}
	}
	else
		(*fld).organizationUnitName = NULL;
	if(tmpFld[5].address != NULL) {
		(*fld).commonName = (unsigned char*)malloc(sizeof(unsigned char) * (tmpFld[5].len + 1));
		if ((*fld).commonName != NULL) {
			memset((*fld).commonName, 0x00, (tmpFld[5].len + 1));
			memcpy((*fld).commonName, (tmpFld[5].address + strlen((const char*)(tmpFld[5].unitName))), tmpFld[5].len);
		}
	}
	else
		(*fld).commonName = NULL;
	if(tmpFld[6].address != NULL) {
		(*fld).emailAddress = (unsigned char*)malloc(sizeof(unsigned char) * (tmpFld[6].len + 1));
		if ((*fld).emailAddress != NULL) {
			memset((*fld).emailAddress, 0x00, (tmpFld[6].len + 1));
			memcpy((*fld).emailAddress, (tmpFld[6].address + strlen((const char*)(tmpFld[6].unitName))), tmpFld[6].len);
		}
	}
	else
		(*fld).emailAddress = NULL;

	return ret;
}

int parse_time_fld_data(unsigned char* before, unsigned char* after, cert_svc_validity_fld_data* fld)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	char* index = NULL;
	char year[5] = {0, };
	char month[3] = {0, };
	char day[3] = {0, };
	char hour[3] = {0, };
	char minute[3] = {0, };
	char second[3] = {0, };

	if((strlen((char*)before) < 15) || (strlen((char*)after) < 15)) {
		SLOGE("[ERR][%s] Fail to parse time fld.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_CERTIFICATE;
		goto err;
	}

	// first(before)
	index = (char*)before;
	strncpy(year, index, 4);
	(*fld).firstYear = (unsigned int)(strtoul(year, NULL, 10));
	strncpy(month, (index + 4), 2);
	(*fld).firstMonth = (unsigned int)(strtoul(month, NULL, 10));
	strncpy(day, (index + 6), 2);
	(*fld).firstDay = (unsigned int)(strtoul(day, NULL, 10));
	strncpy(hour, (index + 8), 2);
	(*fld).firstHour = (unsigned int)(strtoul(hour, NULL, 10));
	strncpy(minute, (index + 10), 2);
	(*fld).firstMinute = (unsigned int)(strtoul(minute, NULL, 10));
	strncpy(second, (index + 12), 2);
	(*fld).firstSecond = (unsigned int)(strtoul(second, NULL, 10));

	// second(after)
	index = (char*)after;
	strncpy(year, index, 4);
	(*fld).secondYear = (unsigned int)(strtoul(year, NULL, 10));
	strncpy(month, (index + 4), 2);
	(*fld).secondMonth = (unsigned int)(strtoul(month, NULL, 10));
	strncpy(day, (index + 6), 2);
	(*fld).secondDay = (unsigned int)(strtoul(day, NULL, 10));
	strncpy(hour, (index + 8), 2);
	(*fld).secondHour = (unsigned int)(strtoul(hour, NULL, 10));
	strncpy(minute, (index + 10), 2);
	(*fld).secondMinute = (unsigned int)(strtoul(minute, NULL, 10));
	strncpy(second, (index + 12), 2);
	(*fld).secondSecond = (unsigned int)(strtoul(second, NULL, 10));

err:
	return ret;
}

cert_svc_linked_list* find_issuer_from_list(cert_svc_linked_list* list, cert_svc_linked_list* p)
{
	/* find q and q has subject string which be same with issuer string of parameter p */
	cert_svc_linked_list* q = NULL;
	cert_svc_cert_descriptor* tmp1 = NULL;
	cert_svc_cert_descriptor* tmp2 = NULL;

	tmp1 = (cert_svc_cert_descriptor*)malloc(sizeof(cert_svc_cert_descriptor));
	if (tmp1 == NULL) {
		SLOGE("[ERR][%s] Fail to allocate certificate descriptor.\n", __func__);
		return NULL;
	}

	memset(tmp1, 0x00, sizeof(cert_svc_cert_descriptor));

	if(_extract_certificate_data(p->certificate, tmp1) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to extract certificate data.\n", __func__);
		goto err;
	}

	for(q = list; q != NULL; q = q->next) {
		tmp2 = (cert_svc_cert_descriptor*)malloc(sizeof(cert_svc_cert_descriptor));
		if (tmp2 == NULL) {
			SLOGE("[ERR][%s] Fail to allocate certificate descriptor.\n", __func__);
			goto err;
		}

		memset(tmp2, 0x00, sizeof(cert_svc_cert_descriptor));

		_extract_certificate_data(q->certificate, tmp2);

		if(!strncmp((const char*)(tmp2->info.subjectStr), (const char*)(tmp1->info.issuerStr), strlen((const char*)(tmp1->info.issuerStr)))) {	// success
			release_certificate_data(tmp1);
			release_certificate_data(tmp2);
			return q;
		}
		release_certificate_data(tmp2);
		tmp2 = NULL;
	}

err:	// fail
	release_certificate_data(tmp1);
	release_certificate_data(tmp2);
	return NULL;
}

int sort_cert_chain(cert_svc_linked_list** unsorted, cert_svc_linked_list** sorted)
{
	cert_svc_linked_list* p = NULL;
	cert_svc_linked_list* q = NULL;
	cert_svc_linked_list* r = NULL;

	cert_svc_cert_descriptor* tmp1 = NULL;
	cert_svc_cert_descriptor* tmp2 = NULL;

	if((*unsorted) == NULL) {
		for(p = (*sorted); p->next != NULL; p = p->next) {
			tmp1 = (cert_svc_cert_descriptor*)malloc(sizeof(cert_svc_cert_descriptor));
			if(tmp1 == NULL) {
				SLOGE("[ERR][%s] Fail to allocate certificate descriptor.\n", __func__);
				return CERT_SVC_ERR_MEMORY_ALLOCATION;
			}
			memset(tmp1, 0x00, sizeof(cert_svc_cert_descriptor));
			tmp2 = (cert_svc_cert_descriptor*)malloc(sizeof(cert_svc_cert_descriptor));
			if(tmp2 == NULL) {
				release_certificate_data(tmp1);
				SLOGE("[ERR][%s] Fail to allocate certificate descriptor.\n", __func__);
				return CERT_SVC_ERR_MEMORY_ALLOCATION;
			}
			memset(tmp2, 0x00, sizeof(cert_svc_cert_descriptor));

			_extract_certificate_data(p->certificate, tmp1);
			_extract_certificate_data(p->next->certificate, tmp2);

			if(strncmp((const char*)(tmp1->info.issuerStr), (const char*)(tmp2->info.subjectStr), strlen((const char*)(tmp2->info.subjectStr)))) {
				SLOGE("[ERR][%s] Certificate chain is broken.\n", __func__);
				release_certificate_data(tmp1);
				release_certificate_data(tmp2);
				return CERT_SVC_ERR_BROKEN_CHAIN;
			}
			else {
				release_certificate_data(tmp1);
				tmp1 = NULL;
				release_certificate_data(tmp2);
				tmp2 = NULL;
			}
		}
		release_certificate_data(tmp1);
		release_certificate_data(tmp2);
		return CERT_SVC_ERR_NO_ERROR;
	}
	else if((*unsorted)->next == NULL) {
		(*unsorted)->next = *sorted;
		*sorted = *unsorted;
		*unsorted = NULL;
	}
	else {
		r = (*unsorted);
		for(p = (*unsorted); p != NULL; p = p->next) {
			if((q = find_issuer_from_list((*unsorted), p)) == NULL)
				break;

			r = p;
		}

		if(q != NULL) {
			SLOGE("[ERR][%s] Certificate chain is broken.\n", __func__);
			return CERT_SVC_ERR_BROKEN_CHAIN;
		}

		if(r == p) {
			q = (*unsorted)->next;
			(*unsorted)->next = (*sorted);
			(*sorted) = (*unsorted);
			(*unsorted) = q;
		}
		else if((*sorted) == NULL) {
			(*sorted) = p;
			r->next = p->next;
			(*sorted)->next = NULL;
		}
		else {
			r->next = p->next;
			p->next = (*sorted);
			(*sorted) = p;
		}
	}

	return sort_cert_chain(unsorted, sorted);
}

int is_CACert(cert_svc_mem_buff* cert, int* isCA)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	X509* x = NULL;
	const unsigned char* p = NULL;

	p = cert->data;
	d2i_X509(&x, &p, cert->size);

	if(x == NULL) {
		SLOGE("[ERR][%s] Certificate cannot be parsed.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_CERTIFICATE;
		goto err;
	}

	if(X509_check_ca(x) > 0)
		(*isCA) = 1;
	else
		(*isCA) = 0;

err:
	if(x != NULL)
		X509_free(x);

	return ret;
}

int compare_period(int year, int month, int day, int hour, int min, int sec, struct tm* tm)
{
	int ret = 0;
	// if return 0 --> same
	// else if return 1 --> tm is bigger
	// else if return -1 --> tm is smaller

	if(tm->tm_year > year) ret = 1;
	else if(tm->tm_year < year) ret = -1;
	else {	// year is same
		if(tm->tm_mon > month) ret = 1;
		else if(tm->tm_mon < month) ret = -1;
		else {	// month is same
			if(tm->tm_mday > day) ret = 1;
			else if(tm->tm_mday < day) ret = -1;
			else {	// day is same
				if(tm->tm_hour > hour) ret = 1;
				else if(tm->tm_hour < hour) ret = -1;
				else {	// hour is same
					if(tm->tm_min > min) ret = 1;
					else if(tm->tm_min < min) ret = -1;
					else {	// minute is same
						if(tm->tm_sec > sec) ret = 1;
						else if(tm->tm_sec < sec) ret = -1;
						else // second is same
							ret = 0;
					}
				}
			}
		}
	}

	return ret;
}

int is_expired(cert_svc_mem_buff* cert, int* isExpired)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_cert_descriptor* certDesc = NULL;
	int visibility = 0;
	time_t t;
	struct tm* tm;
	unsigned char * certdata = NULL;
	int certSize = 0;
	unsigned char *fingerprint = NULL;

	// get current time
	t = time(NULL);
	tm = gmtime(&t);

	// get descriptor
	certDesc = (cert_svc_cert_descriptor*)malloc(sizeof(cert_svc_cert_descriptor));
	if(certDesc == NULL) {
		SLOGE("[ERR][%s] Fail to allocate certificate descriptor.\n", __func__);
		return CERT_SVC_ERR_MEMORY_ALLOCATION;
	}
	memset(certDesc, 0x00, sizeof(cert_svc_cert_descriptor));

	if((ret = _extract_certificate_data(cert, certDesc)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to extract certificate.\n", __func__);
		(*isExpired) = 1;
		goto err;
	}

        certdata = cert->data;
	certSize = cert->size;

	if(certdata == NULL || !certSize)
	{
		SLOGE("cert is or invalid!");
		ret = CERT_SVC_ERR_INVALID_CERTIFICATE;
		(*isExpired) = 1;
		goto err;
	}

	ret = get_certificate_fingerprint(certdata, certSize, &fingerprint);
	if(ret != CERT_SVC_ERR_NO_ERROR)
	{
		SLOGE("Failed to get fingerprint data! %d", ret);
		(*isExpired) = 1;
		goto err;
	}

	ret = get_visibility_by_fingerprint(fingerprint, &visibility);
	if(ret != CERT_SVC_ERR_NO_ERROR)
	{
		SLOGE("Failed to get visibility! %d", ret);
		(*isExpired) = 1;
		goto err;
	}

	if(visibility == CERT_SVC_VISIBILITY_TEST || visibility == CERT_SVC_VISIBILITY_VERIFY)
	{
		// compare with not before - MUST bigger than this
		if(compare_period(((int)certDesc->info.validPeriod.firstYear - 1900),
						  ((int)certDesc->info.validPeriod.firstMonth - 1),
						  (int)certDesc->info.validPeriod.firstDay,
						  (int)certDesc->info.validPeriod.firstHour,
						  (int)certDesc->info.validPeriod.firstMinute,
						  (int)certDesc->info.validPeriod.firstSecond,
						  tm) != 1) {
			SLOGE("[ERR][%s] Certificate is expired.\n", __func__);
			ret = CERT_SVC_ERR_IS_EXPIRED;
			(*isExpired) = 1;
			goto err;
		}

		// compare with not after - MUST smaller than this
		if(compare_period(((int)certDesc->info.validPeriod.secondYear - 1900),
						  ((int)certDesc->info.validPeriod.secondMonth - 1),
						  (int)certDesc->info.validPeriod.secondDay,
						  (int)certDesc->info.validPeriod.secondHour,
						  (int)certDesc->info.validPeriod.secondMinute,
						  (int)certDesc->info.validPeriod.secondSecond,
						  tm) != -1) {
			SLOGE("[ERR][%s] Certificate is expired.\n", __func__);
			ret = CERT_SVC_ERR_IS_EXPIRED;
			(*isExpired) = 1;
			goto err;
		}
	}
	else// ignore check cert time with local time (internal concept)
	{
		(*isExpired) = 0;	// not expired
	}

err:
	release_certificate_data(certDesc);

	return ret;
}

int VerifyCallbackfunc(int ok, X509_STORE_CTX* store)
{
	char buf[256] = {0, };
	struct verify_context* verify_context = (struct verify_context*)X509_STORE_CTX_get_app_data(store);
	verify_context->depth += 1;
	if(store->current_cert != NULL)
		X509_NAME_oneline(X509_get_subject_name(store->current_cert), buf, 256);
	else
		strncpy(buf, "test", 4);
	SECURE_SLOGD("[%s] Certificate %i: %s\n", __func__, verify_context->depth, buf);

	return ok;
}

int _remove_selfsigned_cert_in_chain(cert_svc_linked_list** certList)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_linked_list* prev = NULL;
	cert_svc_linked_list* current = NULL;
	cert_svc_linked_list* start = NULL;
	cert_svc_linked_list* deleted = NULL;
	cert_svc_cert_descriptor* certdesc = NULL;
	int first_tag = 0;

	start = (*certList);
	prev = start;

	for(current = (*certList); current != NULL; current = current->next) {
		deleted = current;

		certdesc = (cert_svc_cert_descriptor*)malloc(sizeof(cert_svc_cert_descriptor));
		if(certdesc == NULL) {
			SLOGE("[ERR][%s] Fail to allocate certificate descriptor.\n", __func__);
			return CERT_SVC_ERR_MEMORY_ALLOCATION;
		}
		memset(certdesc, 0x00, sizeof(cert_svc_cert_descriptor));

		if((ret = _extract_certificate_data(current->certificate, certdesc)) != CERT_SVC_ERR_NO_ERROR) {
			SLOGE("[ERR][%s] Fail to extract certificate data.\n", __func__);
			goto err;
		}

		if(!strncmp((const char*)(certdesc->info.subjectStr), (const char*)(certdesc->info.issuerStr), strlen((const char*)(certdesc->info.issuerStr)))) { // self-signed
			if(first_tag == 0) { // first cert is self-signed
				start = start->next;
				prev = start;

				deleted->next = NULL;
				release_cert_list(deleted);

				release_certificate_data(certdesc);
				certdesc = NULL;
				continue;
			}
			else {
				prev->next = current->next;

				deleted->next = NULL;
				release_cert_list(deleted);
			}
		}
		else {
			prev = current;
		}

		release_certificate_data(certdesc);
		certdesc = NULL;

		first_tag = 1;
	}

	(*certList) = start;

err:
	if(certdesc != NULL)
		release_certificate_data(certdesc);

	return ret;
}

int _verify_certificate(cert_svc_mem_buff* certBuf, cert_svc_linked_list** certList, cert_svc_filename_list* rootPath, int* validity){
	int ca_cflag_check_false = 0;

	return _verify_certificate_with_caflag(certBuf, certList, ca_cflag_check_false, rootPath, validity);
}

int _verify_certificate_with_caflag(cert_svc_mem_buff* certBuf, cert_svc_linked_list** certList, int checkCaFlag, cert_svc_filename_list* rootPath, int* validity)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_linked_list* sorted = NULL;
	cert_svc_linked_list* p = NULL;
	cert_svc_linked_list* q = NULL;
	cert_svc_cert_descriptor* findRoot = NULL;
	cert_svc_filename_list* fileNames = NULL;
	cert_svc_mem_buff* CACert = NULL;
	int isCA = -1, isExpired = -1;
	// variables for verification
	int certNum = 0;
	int certIndex = 0, i = 0;
	const unsigned char* certContent = NULL;
	X509_STORE_CTX* storeCtx = NULL;
	X509* rootCert = NULL;
	X509** interCert = NULL;
	X509* targetCert = NULL;
	STACK_OF(X509) *tchain, *uchain;
	STACK_OF(X509) *resultChain;
	X509* tmpCert = NULL;
	int caFlagValidity;

	OpenSSL_add_all_algorithms();
	tchain = sk_X509_new_null();
	uchain = sk_X509_new_null();

	findRoot = (cert_svc_cert_descriptor*)malloc(sizeof(cert_svc_cert_descriptor));
	if(findRoot == NULL) {
		SLOGE("[ERR][%s] Failed to allocate memory for certificate descriptor.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}

	memset(findRoot, 0x00, sizeof(cert_svc_cert_descriptor));

	if((*certList) != NULL) {
		/* remove self-signed certificate in certList */
		if((ret = _remove_selfsigned_cert_in_chain(certList)) != CERT_SVC_ERR_NO_ERROR) {
			SLOGE("[ERR][%s] Fail to remove self-signed certificate in chain.\n", __func__);
			goto err;
		}
		/* sort certList */
		if((ret = sort_cert_chain(certList, &sorted)) != CERT_SVC_ERR_NO_ERROR) {
			SLOGE("[ERR][%s] Fail to sort certificate chain.\n", __func__);
			goto err;
		}

		/* find root cert from store, the SUBJECT field of root cert is same with ISSUER field of certList[0] */
		p = sorted;
		while(p->next != NULL) {
			certNum++;
			p = p->next;
		}
		certNum++;

		ret = _extract_certificate_data(p->certificate, findRoot);
	}
	else
		ret = _extract_certificate_data(certBuf, findRoot);

	if(ret != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to extract certificate data\n", __func__);
		goto err;
	}

	if((ret = _search_certificate(&fileNames, SUBJECT_STR, (char*)findRoot->info.issuerStr)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to search root certificate\n", __func__);
		goto err;
	}

	if(fileNames->filename == NULL) {
		SLOGE("[ERR][%s] There is no CA certificate.\n", __func__);
		ret = CERT_SVC_ERR_NO_ROOT_CERT;
		goto err;
	}

	CACert = (cert_svc_mem_buff*)malloc(sizeof(cert_svc_mem_buff));
	if(CACert == NULL) {
		SLOGE("[ERR][%s] Failed to allocate memory for ca cert.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}

	memset(CACert, 0x00, sizeof(cert_svc_mem_buff));

	// use the first found CA cert - ignore other certificate(s). assume that there is JUST one CA cert
	if((ret = cert_svc_util_load_file_to_buffer(fileNames->filename, CACert)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to load CA cert to buffer.\n", __func__);
		goto err;
	}

	// store root certicate path into ctx
	strncpy(rootPath->filename, fileNames->filename, CERT_SVC_MAX_FILE_NAME_SIZE - 1);
	rootPath->filename[CERT_SVC_MAX_FILE_NAME_SIZE - 1] = '\0';

	/* check validity - is CA?, is expired? */
	if((ret = is_CACert(CACert, &isCA)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] CA certificate is invalid.\n", __func__);
		goto err;
	}
	if(isCA != 1) {	// NOT CA certificate
		SLOGE("[ERR][%s] Found certificate is NOT CA certificate.\n", __func__);
		ret = CERT_SVC_ERR_NO_ROOT_CERT;
		goto err;
	}

	if((ret = is_expired(CACert, &isExpired)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] CA certificate is invalid.\n", __func__);
		goto err;
	}
	if(isExpired != 0) {	// expired
		SLOGE("[ERR][%s] CA certificate is expired.\n", __func__);
		ret = CERT_SVC_ERR_IS_EXPIRED;
		goto err;
	}

	/* verify */
	// insert root certificate into trusted chain
	certContent = CACert->data;
	d2i_X509(&rootCert, &certContent, CACert->size);
	if(!(sk_X509_push(tchain, rootCert))) {
		SLOGE("[ERR][%s] Fail to push certificate into stack.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}

	certContent = certBuf->data;
	d2i_X509(&targetCert, &certContent, certBuf->size);

	q = sorted; // first item is the certificate that user want to verify

	// insert all certificate(s) into chain
	if(q != NULL) {	// has 2 or more certificates
		certIndex = 0;
		interCert = (X509**)malloc(sizeof(X509*) * certNum);
		if(interCert == NULL) {
			SLOGE("[ERR][%s] Failed to allocate memory for interim certificate.\n", __func__);
			ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
			goto err;
		}

		memset(interCert, 0x00, (sizeof(X509*) * certNum));
		while(1) {
			certContent = q->certificate->data;
			if(!d2i_X509(&interCert[certIndex], &certContent, q->certificate->size)) {
				SLOGE("[ERR][%s] Fail to load certificate into memory.\n", __func__);
				ret = CERT_SVC_ERR_INVALID_CERTIFICATE;
				goto err;
			}
			if(!(sk_X509_push(uchain, interCert[certIndex]))) {
				SLOGE("[ERR][%s] Fail to push certificate into stack.\n", __func__);
				ret = CERT_SVC_ERR_INVALID_OPERATION;
				goto err;
			}

			if(q->next == NULL)
				break;
			else {
				q = q->next;
				certIndex++;
			}
		}
	}

	// initialize store and store context
	storeCtx = X509_STORE_CTX_new();

	// construct store context
	if(!X509_STORE_CTX_init(storeCtx, 0, targetCert, uchain)) {
		SLOGE("[ERR][%s] Fail to initialize X509 store context.\n", __func__);
		goto err;
	}
	struct verify_context verify_context = { 0 };
	X509_STORE_CTX_set_app_data(storeCtx, &verify_context);
	X509_STORE_CTX_set_verify_cb(storeCtx, VerifyCallbackfunc);
	X509_STORE_CTX_trusted_stack(storeCtx, tchain);

	// verify
	if(((*validity) = X509_verify_cert(storeCtx)) != 1) {
		SLOGE("[ERR][%s] Fail to verify certificate chain, validity: [%d]\n", __func__, (*validity));
		SLOGE("err str: [%s]\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(storeCtx)));
		goto err;
	}

	if(checkCaFlag) { // check strictly
		resultChain = X509_STORE_CTX_get1_chain(storeCtx);
		while((tmpCert = sk_X509_pop(resultChain))) {
			caFlagValidity = X509_check_ca(tmpCert);
			if(caFlagValidity != 1 && (tmpCert = sk_X509_pop(resultChain)) != NULL) { // the last one is not a CA.
				(*validity) = 0;
				SLOGE("[ERR][%s] Invalid CA Flag for CA Certificate, validity: [%d]\n", __func__, (*validity));
				break;
			}
		}
	}

err:
	if(rootCert != NULL)
		X509_free(rootCert);
	if(targetCert != NULL)
		X509_free(targetCert);
	if(storeCtx != NULL)
		X509_STORE_CTX_free(storeCtx);
	if(tchain != NULL)
		sk_X509_free(tchain);
	if(uchain != NULL)
		sk_X509_free(uchain);

	if(interCert != NULL) {
		for(i = 0; i < certNum; i++) {
			if(interCert[i] != NULL)
				X509_free(interCert[i]);
		}
		free(interCert);
	}

	EVP_cleanup();
	release_certificate_buf(CACert);
	release_certificate_data(findRoot);
	release_filename_list(fileNames);
	release_cert_list(sorted);

	return ret;
}

int _verify_signature(cert_svc_mem_buff* certBuf, unsigned char* message, int msgLen, unsigned char* signature, char* algo, int* validity)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	X509* x = NULL;
	const unsigned char* p = NULL;
	// hash
	EVP_MD_CTX* mdctx = NULL;
	const EVP_MD* md = NULL;
	// signature
	unsigned char* decodedSig = NULL;
	int decodedSigLen = 0;
	int sigLen = 0;
	// public key
	EVP_PKEY *pkey = NULL;

	OpenSSL_add_all_digests();

	/* load certificate into buffer */
	p = certBuf->data;
	d2i_X509(&x, &p, certBuf->size);
	if(x == NULL) {
		SLOGE("[ERR][%s] Fail to allocate X509 structure.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_CERTIFICATE;
		goto err;
	}

	/* load signature and decode */
	sigLen = strlen((const char*)signature);
	decodedSigLen = ((sigLen / 4) * 3) + 1;

	if(!(decodedSig = (unsigned char*)malloc(sizeof(unsigned char) * decodedSigLen))) {
		SLOGE("[ERR][%s] Fail to allocate memory.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(decodedSig, 0x00, decodedSigLen);
	if((ret = cert_svc_util_base64_decode((char*)signature, sigLen, (char*)decodedSig, &decodedSigLen)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to base64 decode.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}

	/* get public key */
	pkey = X509_get_pubkey(x);

	/* make EVP_MD_CTX */
	mdctx = EVP_MD_CTX_create();
	if(algo == NULL) {	// if hash algorithm is not defined,
		if(!(md = EVP_get_digestbyobj(x->cert_info->signature->algorithm))) {	// get hash algorithm
			SLOGE("[ERR][%s] Fail to get hash algorithm.\n", __func__);
			ret = CERT_SVC_ERR_INVALID_CERTIFICATE;
			goto err;
		}
	}
	else {	// if hash algorithm is defined,
		if(!(md = EVP_get_digestbyname(algo))) {	// get hash algorithm
			SLOGE("[ERR][%s] Fail to get hash algorithm.\n", __func__);
			ret = CERT_SVC_ERR_INVALID_CERTIFICATE;
			goto err;
		}
	}

	/* initialization */
	if(EVP_VerifyInit_ex(mdctx, md, NULL) != 1) {
		SLOGE("[ERR][%s] Fail to execute EVP_VerifyInit_ex().\n", __func__);
		ret = CERT_SVC_ERR_INVALID_CERTIFICATE;
		goto err;
	}
	if(EVP_VerifyUpdate(mdctx, message, msgLen) != 1) {
		SLOGE("[ERR][%s] Fail to execute EVP_VerifyUpdate().\n", __func__);
		ret = CERT_SVC_ERR_INVALID_CERTIFICATE;
		goto err;
	}
	if(((*validity) = EVP_VerifyFinal(mdctx, decodedSig, decodedSigLen, pkey)) != 1) {
		SLOGE("[ERR][%s] Fail to verify signature.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_SIGNATURE;
		goto err;
	}

err:
	if(x != NULL)
		X509_free(x);
	if(decodedSig != NULL)
		free(decodedSig);
	if(pkey != NULL)
		EVP_PKEY_free(pkey);
	if(mdctx != NULL)
		EVP_MD_CTX_destroy(mdctx);
	EVP_cleanup();

	return ret;
}

int _extract_certificate_data(cert_svc_mem_buff* cert, cert_svc_cert_descriptor* certDesc)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	X509* x = NULL;
	const unsigned char* p = NULL;
	int i = 0;
	// get signature algorithm
	char* signatureAlgo = NULL;
	int sigLen = 0;
	// get issuer
	int issuerStrLen = 0;
	unsigned char* tmpIssuerStr = NULL;
	// get time
	ASN1_GENERALIZEDTIME* timeNotBefore = NULL;
	ASN1_GENERALIZEDTIME* timeNotAfter = NULL;
	// get subject
	int subjectStrLen = 0;
	unsigned char* tmpSubjectStr = NULL;
	// get public key algorithm
	char* publicKeyAlgo = NULL;
	int publicKeyAlgoLen = 0;
	// get public key
	unsigned char* pubkeyTmp = NULL;
	int pkeyLen = 0;
	EVP_PKEY* evp = NULL;
	int issuerUidLen = 0, subjectUidLen = 0;
	// get extension values
	X509_EXTENSION* ext = NULL;
	char* extObject = NULL;
	int extObjLen = 0;
	char* extValue = NULL;
	int extValLen = 0;

	// get signature algorithm and signature
	char* sigAlgo = NULL;
	int sigAlgoLen = 0, sigDataLen = 0;

	memset(certDesc, 0x00, sizeof(cert_svc_cert_descriptor));

	p = cert->data;
	d2i_X509(&x, &p, cert->size);
	if(x == NULL) {
		SLOGE("[ERR][%s] Fail to allocate X509 structure.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_CERTIFICATE;
		goto err;
	}

	/* get type */
	strncpy(certDesc->type, cert->type, 3);
	certDesc->type[3] = '\0';
	/* get version and serial number */
	certDesc->info.version = get_ASN1_INTEGER(x->cert_info->version) + 1;	// default is 0 --> version 1
	certDesc->info.serialNumber = get_ASN1_INTEGER(x->cert_info->serialNumber);
	/* get signature algorithm */
	signatureAlgo = (char*)get_ASN1_OBJECT(x->cert_info->signature->algorithm);
	sigLen = strlen((const char*)signatureAlgo);
	certDesc->info.sigAlgo = (unsigned char*)malloc(sizeof(unsigned char) * (sigLen + 1));
	if(certDesc->info.sigAlgo == NULL) {
		SLOGE("[ERR][%s] Failed to allocate memory.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(certDesc->info.sigAlgo, 0x00, (sigLen + 1));
	memcpy(certDesc->info.sigAlgo, signatureAlgo, sigLen);
	/* get issuer */
	tmpIssuerStr = (unsigned char*)get_X509_NAME(x->cert_info->issuer);
	issuerStrLen = strlen((const char*)tmpIssuerStr);
	certDesc->info.issuerStr = (unsigned char*)malloc(sizeof(unsigned char) * (issuerStrLen + 1));
	if(certDesc->info.issuerStr == NULL) {
		SLOGE("[ERR][%s] Failed to allocate memory.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(certDesc->info.issuerStr, 0x00, (issuerStrLen + 1));
	memcpy(certDesc->info.issuerStr, tmpIssuerStr, issuerStrLen);

	if((ret = parse_name_fld_data(tmpIssuerStr, &(certDesc->info.issuer))) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to parse cert_svc_name_fld_data.\n", __func__);
		goto err;
	}
	/* get time */
	ASN1_TIME_to_generalizedtime(x->cert_info->validity->notBefore, &timeNotBefore);
	ASN1_TIME_to_generalizedtime(x->cert_info->validity->notAfter, &timeNotAfter);
	if((ret = parse_time_fld_data(timeNotBefore->data, timeNotAfter->data, &(certDesc->info.validPeriod))) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to parse cert_svc_validity_fld_data.\n", __func__);
		goto err;
	}
	/* get subject */
	tmpSubjectStr = (unsigned char*)get_X509_NAME(x->cert_info->subject);
	subjectStrLen = strlen((const char*)tmpSubjectStr);
	certDesc->info.subjectStr = (unsigned char*)malloc(sizeof(unsigned char) * (subjectStrLen + 1));
	if(certDesc->info.subjectStr == NULL) {
		SLOGE("[ERR][%s] Failed to allocate memory.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(certDesc->info.subjectStr, 0x00, (subjectStrLen + 1));
	memcpy(certDesc->info.subjectStr, tmpSubjectStr, subjectStrLen);

	if((ret = parse_name_fld_data(tmpSubjectStr, &(certDesc->info.subject))) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to parse cert_svc_name_fld_data.\n", __func__);
		goto err;
	}
	/* get public key algorithm */
	publicKeyAlgo = (char*)get_ASN1_OBJECT(x->cert_info->key->algor->algorithm);
	publicKeyAlgoLen = strlen((const char*)publicKeyAlgo);
	certDesc->info.pubKeyAlgo = (unsigned char*)malloc(sizeof(unsigned char) * (publicKeyAlgoLen + 1));
	if(certDesc->info.pubKeyAlgo == NULL) {
		SLOGE("[ERR][%s] Failed to allocate memory.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(certDesc->info.pubKeyAlgo, 0x00, (publicKeyAlgoLen + 1));
	memcpy(certDesc->info.pubKeyAlgo, publicKeyAlgo, publicKeyAlgoLen);
	/* get public key */
	if((evp = X509_get_pubkey(x)) == NULL) {
		SLOGE("[ERR][%s] Public key is null.\n", __func__);
		ret = CERT_SVC_ERR_INVALID_CERTIFICATE;
		goto err;
	}
	pkeyLen = i2d_PublicKey(x->cert_info->key->pkey, NULL);
	certDesc->info.pubKey = (unsigned char*)malloc(sizeof(unsigned char) * (pkeyLen + 1));
	if(certDesc->info.pubKey == NULL) {
		SLOGE("[ERR][%s] Failed to allocate memory.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	pubkeyTmp = certDesc->info.pubKey;
	i2d_PublicKey(x->cert_info->key->pkey, &pubkeyTmp);
	certDesc->info.pubKeyLen = pkeyLen;
	/* get issuer UID */
	if(x->cert_info->issuerUID != NULL) {
		issuerUidLen = x->cert_info->issuerUID->length;
		certDesc->info.issuerUID = (unsigned char*)malloc(sizeof(unsigned char) * (issuerUidLen + 1));
		if(certDesc->info.issuerUID == NULL) {
			SLOGE("[ERR][%s] Failed to allocate memory.\n", __func__);
			ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
			goto err;
		}
		memset(certDesc->info.issuerUID, 0x00, (issuerUidLen + 1));
		memcpy(certDesc->info.issuerUID, x->cert_info->issuerUID->data, issuerUidLen);
	}
	else
		certDesc->info.issuerUID = NULL;

	/* get subject UID */
	if(x->cert_info->subjectUID != NULL) {
		subjectUidLen = x->cert_info->subjectUID->length;
		certDesc->info.subjectUID = (unsigned char*)malloc(sizeof(unsigned char) * (subjectUidLen + 1));
		if(certDesc->info.subjectUID == NULL) {
			SLOGE("[ERR][%s] Failed to allocate memory.\n", __func__);
			ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
			goto err;
		}
		memset(certDesc->info.subjectUID, 0x00, (subjectUidLen + 1));
		memcpy(certDesc->info.subjectUID, x->cert_info->subjectUID->data, subjectUidLen);
	}
	else
		certDesc->info.subjectUID = NULL;
	/* get extension fields */
	if(x->cert_info->extensions != NULL) {
//		certDesc->ext.numOfFields = x->cert_info->extensions->num;
		certDesc->ext.numOfFields = sk_X509_EXTENSION_num(x->cert_info->extensions);
		certDesc->ext.fields = (cert_svc_cert_fld_desc*)malloc(sizeof(cert_svc_cert_fld_desc) * certDesc->ext.numOfFields);
		if(certDesc->ext.fields == NULL) {
			SLOGE("[ERR][%s] Failed to allocate memory.\n", __func__);
			ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
			goto err;
		}

		for(i = 0; i < (int)certDesc->ext.numOfFields; i++) {
			ext = sk_X509_EXTENSION_value(x->cert_info->extensions, i);
			if(ext != NULL) {
				extObject = (char*)get_ASN1_OBJECT(ext->object);
				extObjLen = strlen((const char*)extObject);
				certDesc->ext.fields[i].name = (unsigned char*)malloc(sizeof(unsigned char) * (extObjLen + 1));
				if(certDesc->ext.fields[i].name == NULL) {
					SLOGE("[ERR][%s] Failed to allocate memory.\n", __func__);
					ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
					goto err;
				}
				memset(certDesc->ext.fields[i].name, 0x00, (extObjLen + 1));
				memcpy(certDesc->ext.fields[i].name, extObject, extObjLen);

				extValue = (char*)ext->value->data;
				extValLen = ext->value->length;
				certDesc->ext.fields[i].data = (unsigned char*)malloc(sizeof(unsigned char) * (extValLen + 1));
				if(certDesc->ext.fields[i].data == NULL) {
					SLOGE("[ERR][%s] Failed to allocate memory.\n", __func__);
					ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
					goto err;
				}
				memset(certDesc->ext.fields[i].data, 0x00, (extValLen + 1));
				memcpy(certDesc->ext.fields[i].data, extValue, extValLen);

				certDesc->ext.fields[i].datasize = extValLen;
			}
		}
	}
	/* get signature algorithm and signature */
	sigAlgo = (char*)get_ASN1_OBJECT(x->sig_alg->algorithm);
	sigAlgoLen = strlen((const char*)sigAlgo);
	certDesc->signatureAlgo = (unsigned char*)malloc(sizeof(unsigned char) * (sigAlgoLen + 1));
	if(certDesc->signatureAlgo == NULL) {
		SLOGE("[ERR][%s] Failed to allocate memory.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(certDesc->signatureAlgo, 0x00, (sigAlgoLen + 1));
	memcpy(certDesc->signatureAlgo, sigAlgo, sigAlgoLen);

	sigDataLen = x->signature->length;
	certDesc->signatureLen = sigDataLen;
	certDesc->signatureData = (unsigned char*)malloc(sizeof(unsigned char) * (sigDataLen + 1));
	if(certDesc->signatureData == NULL) {
		SLOGE("[ERR][%s] Failed to allocate memory.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(certDesc->signatureData, 0x00, (sigDataLen + 1));
	memcpy(certDesc->signatureData, x->signature->data, sigDataLen);

err:
	if(x != NULL) X509_free(x);
	if(evp != NULL) EVP_PKEY_free(evp);

	if(tmpIssuerStr != NULL) OPENSSL_free(tmpIssuerStr);
	if(tmpSubjectStr != NULL) OPENSSL_free(tmpSubjectStr);

	if(timeNotBefore != NULL) ASN1_GENERALIZEDTIME_free(timeNotBefore);
	if(timeNotAfter != NULL) ASN1_GENERALIZEDTIME_free(timeNotAfter);

	return ret;
}

int search_data_field(search_field fldName, char* fldData, cert_svc_cert_descriptor* certDesc)
{
	int ret = -1;
	int len = 0;

	switch(fldName) {
		case ISSUER_COUNTRY:
			if(certDesc->info.issuer.countryName) {
				len = strlen((const char*)(certDesc->info.issuer.countryName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.issuer.countryName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case ISSUER_STATEORPROVINCE:
			if(certDesc->info.issuer.stateOrProvinceName) {
				len = strlen((const char*)(certDesc->info.issuer.stateOrProvinceName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.issuer.stateOrProvinceName), len)) {
					if((int)strlen(fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case ISSUER_LOCALITY:
			if(certDesc->info.issuer.localityName) {
				len = strlen((const char*)(certDesc->info.issuer.localityName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.issuer.localityName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case ISSUER_ORGANIZATION:
			if(certDesc->info.issuer.organizationName) {
				len = strlen((const char*)(certDesc->info.issuer.organizationName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.issuer.organizationName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case ISSUER_ORGANIZATIONUNIT:
			if(certDesc->info.issuer.organizationUnitName) {
				len = strlen((const char*)(certDesc->info.issuer.organizationUnitName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.issuer.organizationUnitName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case ISSUER_COMMONNAME:
			if(certDesc->info.issuer.commonName) {
				len = strlen((const char*)(certDesc->info.issuer.commonName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.issuer.commonName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case ISSUER_EMAILADDRESS:
			if(certDesc->info.issuer.emailAddress) {
				len = strlen((const char*)(certDesc->info.issuer.emailAddress));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.issuer.emailAddress), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case ISSUER_STR:
			if(certDesc->info.issuerStr) {
				len = strlen((const char*)(certDesc->info.issuerStr));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.issuerStr), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case SUBJECT_COUNTRY:
			if(certDesc->info.subject.countryName) {
				len = strlen((const char*)(certDesc->info.subject.countryName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.subject.countryName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case SUBJECT_STATEORPROVINCE:
			if(certDesc->info.subject.stateOrProvinceName) {
				len = strlen((const char*)(certDesc->info.subject.stateOrProvinceName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.subject.stateOrProvinceName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case SUBJECT_LOCALITY:
			if(certDesc->info.subject.localityName) {
				len = strlen((const char*)(certDesc->info.subject.localityName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.subject.localityName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case SUBJECT_ORGANIZATION:
			if(certDesc->info.subject.organizationName) {
				len = strlen((const char*)(certDesc->info.subject.organizationName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.subject.organizationName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case SUBJECT_ORGANIZATIONUNIT:
			if(certDesc->info.subject.organizationUnitName) {
				len = strlen((const char*)(certDesc->info.subject.organizationUnitName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.subject.organizationUnitName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case SUBJECT_COMMONNAME:
			if(certDesc->info.subject.commonName) {
				len = strlen((const char*)(certDesc->info.subject.commonName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.subject.commonName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case SUBJECT_EMAILADDRESS:
			if(certDesc->info.subject.emailAddress) {
				len = strlen((const char*)(certDesc->info.subject.emailAddress));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.subject.emailAddress), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case SUBJECT_STR:
			if(certDesc->info.subjectStr) {
				len = strlen((const char*)(certDesc->info.subjectStr));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.subjectStr), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		default:
			ret = 0;
	}

	return ret;
}

int _get_all_certificates(char* const *paths, cert_svc_filename_list **lst) {
    int ret = CERT_SVC_ERR_NO_ERROR;
    FTS *fts = NULL;
    FTSENT *ftsent;

    char tmp[10];
    int len;
    cert_svc_filename_list *local = NULL;
    cert_svc_filename_list *el;

    if (NULL == (fts = fts_open(paths, FTS_LOGICAL, NULL))) {
        ret = CERT_SVC_ERR_FILE_IO;
        SLOGE("[ERR][%s] Fail to open directories.\n", __func__);
        goto out;
    }

    while ((ftsent = fts_read(fts)) != NULL) {

        if (ftsent->fts_info == FTS_ERR || ftsent->fts_info == FTS_NS) {
            ret = CERT_SVC_ERR_FILE_IO;
            SLOGE("[ERR][%s] Fail to read directories.\n", __func__);
            goto out;
        }

        if (ftsent->fts_info != FTS_F)
            continue;

        if (-1 != readlink(ftsent->fts_path, tmp, 10))
            continue;

        el = (cert_svc_filename_list*)malloc(sizeof(cert_svc_filename_list));
        if (!el) {
            ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
            SLOGE("[ERR][%s] Fail to allocate memory.\n", __func__);
            goto out;
        }
        el->next = local;
        local = el;

        len = strlen((const char*)(ftsent->fts_path));
        local->filename = (char*)malloc(len+1);
        if (!local->filename) {
            ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
            SLOGE("[ERR][%s] Fail to allocate memory.\n", __func__);
            goto out;
        }
        strncpy(local->filename, ftsent->fts_path, len+1);
    }

    *lst = local;
    local = NULL;

out:
    while (local) {
        el = local;
        local = local->next;
        free(el->filename);
        free(el);
    }

    if (fts != NULL)
        fts_close(fts);
    return ret;
}

int get_all_certificates(cert_svc_filename_list** allCerts)
{
    int ret;
    char ** buffer[] = {(char **)CERT_SVC_SEARCH_PATH_RO, (char **)CERT_SVC_SEARCH_PATH_RW, NULL};

    if (!allCerts) {
        SLOGE("[ERR][%s] Invalid argument.\n", __func__);
        return CERT_SVC_ERR_INVALID_PARAMETER;
    }

    if ((ret = _get_all_certificates((char* const *) buffer, allCerts)) != CERT_SVC_ERR_NO_ERROR) {
        SLOGE("[ERR][%s] Fail to get filelist.\n", __func__);
        return ret;
    }

    return CERT_SVC_ERR_NO_ERROR;
}

int _search_certificate(cert_svc_filename_list** fileNames, search_field fldName, char* fldData)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_filename_list* allCerts = NULL;
	cert_svc_filename_list* p = NULL;
	cert_svc_filename_list* q = NULL;
	cert_svc_filename_list* newNode = NULL;
	cert_svc_mem_buff* certBuf = NULL;
	cert_svc_cert_descriptor* certDesc = NULL;
	int matched = 0;
	struct stat file_info;

	if((ret = get_all_certificates(&allCerts)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to get all certificate file list, ret: [%d]\n", __func__, ret);
		goto err;
	}

	/* if match, store certificate file path into fileNames */
	p = allCerts;

	while(1) {
		if((lstat(p->filename, &file_info)) < 0) {	// get file information
			SECURE_SLOGE("[ERR][%s] Fail to get file(%s) information.\n", __func__, p->filename);
			ret = CERT_SVC_ERR_INVALID_OPERATION;
			goto err;
		}
		if((file_info.st_mode & S_IFLNK) == S_IFLNK) {	// if symbolic link, continue
//			SLOGD("[LOG][%s] %s is symbolic link, ignored.\n", __func__, p->filename);
			goto fail_to_load_file;
		}

		// allocate memory
		if(!(certBuf = (cert_svc_mem_buff*)malloc(sizeof(cert_svc_mem_buff)))) {
			SLOGE("[ERR][%s] Fail to allocate memory.\n", __func__);
			ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
			goto err;
		}

		// load content into buffer
		if((ret = cert_svc_util_load_file_to_buffer(p->filename, certBuf)) != CERT_SVC_ERR_NO_ERROR) {
			SECURE_SLOGE("[ERR][%s] Fail to load file to buffer, filename: [%s], ret: [%d]\n", __func__, p->filename, ret);
			free(certBuf);
			certBuf = NULL;
			goto fail_to_load_file;
		}

		// allocate memory
		if(!(certDesc = (cert_svc_cert_descriptor*)malloc(sizeof(cert_svc_cert_descriptor)))) {
			SLOGE("[ERR][%s] Fail to allocate memory.\n", __func__);
			ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
			goto err;
		}

		// load content into descriptor buffer
		if((ret = _extract_certificate_data(certBuf, certDesc)) != CERT_SVC_ERR_NO_ERROR) {
			SECURE_SLOGE("[ERR][%s] Fail to extract certificate data, filename: [%s], ret: [%d]\n", __func__, p->filename, ret);
			goto fail_to_extract_file;
		}

		// search
		if(search_data_field(fldName, fldData, certDesc) == 1) {	// found!!
			matched = 1;

			if(!(newNode = (cert_svc_filename_list*)malloc(sizeof(cert_svc_filename_list)))) {
				SLOGE("[ERR][%s] Fail to allocate memory.\n", __func__);
				ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
				goto err;
			}
			if(!(newNode->filename = (char*)malloc(sizeof(char) * CERT_SVC_MAX_FILE_NAME_SIZE))) {
				SLOGE("[ERR][%s] Fail to allocate memory.\n", __func__);
				ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
				free(newNode);
				goto err;
			}
			memset(newNode->filename, 0x00, CERT_SVC_MAX_FILE_NAME_SIZE);

			strncpy(newNode->filename, p->filename, CERT_SVC_MAX_FILE_NAME_SIZE - 1);
			newNode->filename[CERT_SVC_MAX_FILE_NAME_SIZE - 1] = '\0';

			newNode->next = NULL;

			if((*fileNames) == NULL)
				(*fileNames) = newNode;
			else {
				q = (*fileNames);
				while(q->next != NULL)
					q = q->next;

				q->next = newNode;
			}
		}

fail_to_extract_file:
		// free allocated memory - certBuf, certDesc
		release_certificate_buf(certBuf);
		certBuf = NULL;
		release_certificate_data(certDesc);
		certDesc = NULL;

fail_to_load_file:
		if(p->next == NULL)
			break;
		p = p->next;
	}

	if(matched != 1) {	// not founded
		SLOGE("[ERR][%s] Cannot find any certificate you want.\n", __func__);
		ret = CERT_SVC_ERR_NO_MORE_CERTIFICATE;
	}
	else
		ret = CERT_SVC_ERR_NO_ERROR;

err:
	release_certificate_buf(certBuf);
	release_certificate_data(certDesc);
	release_filename_list(allCerts);

	return ret;
}
X509 *__loadCert(const char *file) {
	FILE *fp = fopen(file, "r");
	if(fp == NULL)
		return NULL;
	X509 *cert;
	if(!(cert = d2i_X509_fp(fp, NULL))) {
		fseek(fp, 0, SEEK_SET);
		cert = PEM_read_X509(fp, NULL, NULL, NULL);
	}
	fclose(fp);
	return cert;
}

int __loadSystemCerts(STACK_OF(X509) *systemCerts) {
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_filename_list* allCerts = NULL;
	cert_svc_filename_list* p = NULL;
	struct stat file_info;
	X509 *cert;

	if((ret = get_all_certificates(&allCerts)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to get all certificate file list, ret: [%d]\n", __func__, ret);
		goto err;
	}

	p = allCerts;
	while(1) {
		if((lstat(p->filename, &file_info)) < 0) {	// get file information
			SECURE_SLOGE("[ERR][%s] Fail to get file(%s) information.\n", __func__, p->filename);
			ret = CERT_SVC_ERR_INVALID_OPERATION;
			goto err;
		}
		if((file_info.st_mode & S_IFLNK) == S_IFLNK) {	// if symbolic link, continue
//			SLOGD("[LOG][%s] %s is symbolic link, ignored.\n", __func__, p->filename);
			goto fail_to_load_file;
		}

		cert = __loadCert(p->filename);
		if(cert != NULL) {
		    sk_X509_push(systemCerts, cert);
		}
fail_to_load_file:
		if(p->next == NULL)
			break;
		p = p->next;
	}

	ret = CERT_SVC_ERR_NO_ERROR;
err:
	release_filename_list(allCerts);

	return ret;
}

#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
int __ocsp_verify(X509 *cert, X509 *issuer, STACK_OF(X509) *systemCerts, char *url, int *ocspStatus) {
    OCSP_REQUEST *req = NULL;
    OCSP_RESPONSE *resp = NULL;
    OCSP_BASICRESP *bs = NULL;
    OCSP_CERTID *certid = NULL;
    BIO *cbio = NULL;
    SSL_CTX *use_ssl_ctx = NULL;
    char *host = NULL, *port = NULL, *path = NULL;
    ASN1_GENERALIZEDTIME *rev = NULL;
    ASN1_GENERALIZEDTIME *thisupd = NULL;
    ASN1_GENERALIZEDTIME *nextupd = NULL;
    int use_ssl = 0;
    X509_OBJECT obj;
    int i,tmpIdx;
    long nsec = (5 * 60), maxage = -1; /* Maximum leeway in validity period: default 5 minutes */
    int ret = 0;
    char subj_buf[256];
    int reason;
    X509_STORE *trustedStore=NULL;

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

    if (!OCSP_parse_url(url, &host, &port, &path, &use_ssl)) {
        /* report error */
        return CERT_SVC_ERR_OCSP_NO_SUPPORT;
    }

    cbio = BIO_new_connect(host);
    if (!cbio) {
        /*BIO_printf(bio_err, "Error creating connect BIO\n");*/
        /* report error */
        return CERT_SVC_ERR_OCSP_NO_SUPPORT;
    }

    if (port) {
        BIO_set_conn_port(cbio, port);
    }

    if (use_ssl == 1) {
        BIO *sbio;
        use_ssl_ctx = SSL_CTX_new(SSLv23_client_method());
        if (!use_ssl_ctx) {
            /* report error */
            return CERT_SVC_ERR_OCSP_INTERNAL;
        }

        SSL_CTX_set_mode(use_ssl_ctx, SSL_MODE_AUTO_RETRY);
        sbio = BIO_new_ssl(use_ssl_ctx, 1);
        if (!sbio) {
            /* report error */
            return CERT_SVC_ERR_OCSP_INTERNAL;
        }

        cbio = BIO_push(sbio, cbio);
        if (!cbio) {
            /* report error */
            return CERT_SVC_ERR_OCSP_INTERNAL;
        }
    }

    if (BIO_do_connect(cbio) <= 0) {
        /*BIO_printf(bio_err, "Error connecting BIO\n");*/
        /* report error */
        /* free stuff */
        if (host)
            OPENSSL_free(host);
        if (port)
            OPENSSL_free(port);
        if (path)
            OPENSSL_free(path);
        host = port = path = NULL;
        if (use_ssl && use_ssl_ctx)
            SSL_CTX_free(use_ssl_ctx);
        use_ssl_ctx = NULL;
        if (cbio)
            BIO_free_all(cbio);
        cbio = NULL;
        return CERT_SVC_ERR_OCSP_NETWORK_FAILED;
    }

    req = OCSP_REQUEST_new();
    if(!req) {
        return CERT_SVC_ERR_OCSP_INTERNAL;
    }
    certid = OCSP_cert_to_id(NULL, cert, issuer);
    if(certid == NULL)  {
    	return CERT_SVC_ERR_OCSP_INTERNAL;
    }

    if(!OCSP_request_add0_id(req, certid)) {
        return CERT_SVC_ERR_OCSP_INTERNAL;
    }

    resp = OCSP_sendreq_bio(cbio, path, req);

    /* free some stuff we no longer need */
    if (host)
        OPENSSL_free(host);
    if (port)
        OPENSSL_free(port);
    if (path)
        OPENSSL_free(path);
    host = port = path = NULL;
    if (use_ssl && use_ssl_ctx)
        SSL_CTX_free(use_ssl_ctx);
    use_ssl_ctx = NULL;
    if (cbio)
        BIO_free_all(cbio);
    cbio = NULL;

    if (!resp) {
        /*BIO_printf(bio_err, "Error querying OCSP responsder\n");*/
        /* report error */
        /* free stuff */
        OCSP_REQUEST_free(req);
        return CERT_SVC_ERR_OCSP_NETWORK_FAILED;
    }

    i = OCSP_response_status(resp);

    if (i != 0) { // OCSP_RESPONSE_STATUS_SUCCESSFUL
        /*BIO_printf(out, "Responder Error: %s (%ld)\n",
                   OCSP_response_status_str(i), i); */
        /* report error */
        /* free stuff */
        OCSP_REQUEST_free(req);
        OCSP_RESPONSE_free(resp);
        return CERT_SVC_ERR_OCSP_REMOTE;
    }

    bs = OCSP_response_get1_basic(resp);
    if (!bs) {
       /* BIO_printf(bio_err, "Error parsing response\n");*/
        /* report error */
        /* free stuff */
        OCSP_REQUEST_free(req);
        OCSP_RESPONSE_free(resp);
        return CERT_SVC_ERR_OCSP_REMOTE;
    }

    if(systemCerts != NULL) {
        trustedStore = X509_STORE_new();
        for(tmpIdx=0; tmpIdx<sk_X509_num(systemCerts); tmpIdx++) {
        	X509_STORE_add_cert(trustedStore, sk_X509_value(systemCerts, tmpIdx));
        }
        X509_STORE_add_cert(trustedStore, issuer);
    }

	int response = OCSP_basic_verify(bs, NULL, trustedStore, 0);
	if (response <= 0) {
		OCSP_REQUEST_free(req);
		OCSP_RESPONSE_free(resp);
		OCSP_BASICRESP_free(bs);
        X509_STORE_free(trustedStore);

//        int err = ERR_get_error();
//        char errStr[100];
//        ERR_error_string(err,errStr);
//        printf("OCSP_basic_verify fail.error = %s\n", errStr);
		return CERT_SVC_ERR_OCSP_VERIFICATION_ERROR;
	}

    if ((i = OCSP_check_nonce(req, bs)) <= 0) {
        if (i == -1) {
            /*BIO_printf(bio_err, "WARNING: no nonce in response\n");*/
        } else {
            /*BIO_printf(bio_err, "Nonce Verify error\n");*/
            /* report error */
            /* free stuff */
            OCSP_REQUEST_free(req);
            OCSP_RESPONSE_free(resp);
            OCSP_BASICRESP_free(bs);
            X509_STORE_free(trustedStore);
            return CERT_SVC_ERR_OCSP_REMOTE;
        }
    }

    ret = CERT_SVC_ERR_NO_ERROR;

    (void)X509_NAME_oneline(X509_get_subject_name(cert), subj_buf, 255);
    if(!OCSP_resp_find_status(bs, certid, ocspStatus, &reason,
                              &rev, &thisupd, &nextupd)) {
        /* report error */

        /* free stuff */
        OCSP_RESPONSE_free(resp);
        OCSP_REQUEST_free(req);
        OCSP_BASICRESP_free(bs);
        X509_STORE_free(trustedStore);

        return CERT_SVC_ERR_OCSP_REMOTE;
    }

    /* Check validity: if invalid write to output BIO so we
     * know which response this refers to.
     */
    if (!OCSP_check_validity(thisupd, nextupd, nsec, maxage)) {
        /* ERR_print_errors(out); */
        /* report error */

        /* free stuff */
        OCSP_REQUEST_free(req);
        OCSP_RESPONSE_free(resp);
        OCSP_BASICRESP_free(bs);
        X509_STORE_free(trustedStore);

        return CERT_SVC_ERR_OCSP_VERIFICATION_ERROR;
    }

    if (req) {
        OCSP_REQUEST_free(req);
        req = NULL;
    }

    if (resp) {
        OCSP_RESPONSE_free(resp);
        resp = NULL;
    }

    if (bs) {
        OCSP_BASICRESP_free(bs);
        bs = NULL;
    }

    if(trustedStore) {
    	X509_STORE_free(trustedStore);
    	trustedStore = NULL;
    }

    if (reason != -1) {
        char *reason_str = NULL;
        reason_str = OCSP_crl_reason_str(reason);
    }


    return ret;
}

int _check_ocsp_status(cert_svc_mem_buff* certBuf, cert_svc_linked_list** certList, const char* uri)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	int ocspStatus;
	cert_svc_linked_list* sorted = NULL;
	cert_svc_linked_list* p = NULL;
	cert_svc_linked_list* q = NULL;
	cert_svc_cert_descriptor* findRoot = NULL;
	cert_svc_filename_list* fileNames = NULL;
	cert_svc_mem_buff* CACert = NULL;
	// variables for verification
	int certNum = 0;
	cert_svc_mem_buff* childCert;
	cert_svc_mem_buff* parentCert;

	findRoot = (cert_svc_cert_descriptor*)malloc(sizeof(cert_svc_cert_descriptor));
	if(findRoot == NULL) {
		SLOGE("[ERR][%s] Failed to allocate memory for certificate descriptor.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}

	memset(findRoot, 0x00, sizeof(cert_svc_cert_descriptor));
	if(certList != NULL && (*certList) != NULL) {
		/* remove self-signed certificate in certList */
		if((ret = _remove_selfsigned_cert_in_chain(certList)) != CERT_SVC_ERR_NO_ERROR) {
			SLOGE("[ERR][%s] Fail to remove self-signed certificate in chain.\n", __func__);
			goto err;
		}
		/* sort certList */
		if((ret = sort_cert_chain(certList, &sorted)) != CERT_SVC_ERR_NO_ERROR) {
			SLOGE("[ERR][%s] Fail to sort certificate chain.\n", __func__);
			goto err;
		}

		/* find root cert from store, the SUBJECT field of root cert is same with ISSUER field of certList[0] */
		p = sorted;
		while(p->next != NULL) {
			certNum++;
			p = p->next;
		}
		certNum++;
		ret = _extract_certificate_data(p->certificate, findRoot);
	}
	else {
		ret = _extract_certificate_data(certBuf, findRoot);
	}

	if(ret != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to extract certificate data\n", __func__);
		goto err;
	}
	if((ret = _search_certificate(&fileNames, SUBJECT_STR, findRoot->info.issuerStr)) != CERT_SVC_ERR_NO_ERROR) {
		ret = CERT_SVC_ERR_NO_ROOT_CERT;
		SLOGE("[ERR][%s] Fail to search root certificate\n", __func__);
		goto err;
	}
	if(fileNames->filename == NULL) {
		SLOGE("[ERR][%s] There is no CA certificate.\n", __func__);
		ret = CERT_SVC_ERR_NO_ROOT_CERT;
		goto err;
	}

	CACert = (cert_svc_mem_buff*)malloc(sizeof(cert_svc_mem_buff));
	if(CACert == NULL) {
		SLOGE("[ERR][%s] Failed to allocate memory for ca cert.\n", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(CACert, 0x00, sizeof(cert_svc_mem_buff));
	// use the first found CA cert - ignore other certificate(s). assume that there is JUST one CA cert
	if((ret = cert_svc_util_load_file_to_buffer(fileNames->filename, CACert)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to load CA cert to buffer.\n", __func__);
		goto err;
	}
	// =============================
	q = sorted; // first item is the certificate that user want to verify

	childCert = certBuf;
	// To check oscp for all certificate chain except root
	if(q != NULL) {	// has 2 or more certificates
		for( ; q != NULL; q = q->next) {
			parentCert = q->certificate;
			// OCSP Check
			if(CERT_SVC_ERR_NO_ERROR != (ret = _verify_ocsp(childCert, parentCert, uri, &ocspStatus))) {
				SLOGE("[ERR][%s] Error Occurred during OCSP Checking.\n", __func__);
				goto err;
			}
			if(ocspStatus != 0) { // CERT_SVC_OCSP_GOOD
				SLOGE("[ERR][%s] Invalid Certificate OCSP Status. ocspStatus=%d.\n", __func__, ocspStatus);

				switch(ocspStatus) {
				case 0 : //OCSP_GOOD
					ret = CERT_SVC_ERR_NO_ERROR;
					break;
				case 1 : //OCSP_REVOCKED
					ret = CERT_SVC_ERR_OCSP_REVOKED;
					break;
				case 2 : //OCSP_UNKNOWN
					ret = CERT_SVC_ERR_OCSP_UNKNOWN;
					break;
				default :
					ret = CERT_SVC_ERR_OCSP_REMOTE;
					break;
				}
				goto err;
			}

			// move to next
			childCert = parentCert;
		}
	}

	// Final OCSP Check
	parentCert = CACert;
	if(CERT_SVC_ERR_NO_ERROR != (ret = _verify_ocsp(childCert, parentCert, uri, &ocspStatus))) {
		SLOGE("[ERR][%s] Error Occurred during OCSP Checking.\n", __func__);
		goto err;
	}
	switch(ocspStatus) {
	case 0 : //OCSP_GOOD
		ret = CERT_SVC_ERR_NO_ERROR;
		break;
	case 1 : //OCSP_REVOCKED
		ret = CERT_SVC_ERR_OCSP_REVOKED;
		break;
	case 2 : //OCSP_UNKNOWN
		ret = CERT_SVC_ERR_OCSP_UNKNOWN;
		break;
	default :
		ret = CERT_SVC_ERR_OCSP_REMOTE;
		break;
	}
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Invalid Certificate OCSP Status. ocspStatus=%d.\n", __func__, ocspStatus);
		goto err;
	}
	// =============================
err:
	release_certificate_buf(CACert);
	release_filename_list(fileNames);
	release_certificate_data(findRoot);
	release_cert_list(sorted);
	return ret;
}

int _verify_ocsp(cert_svc_mem_buff* child, cert_svc_mem_buff* parent, const char* uri, int* ocspStatus)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	X509 *childCert = NULL;
	X509 *parentCert= NULL;
	char *childData=NULL;
	char *parentData=NULL;
	char *certAiaUrl= NULL;
	char *targetUrl= NULL;
	STACK_OF(OPENSSL_STRING) *aia = NULL;
    STACK_OF(X509) *systemCerts=NULL;
    int i;
	childData = malloc(child->size + 1);
	memset(childData, 0x00, (child->size + 1));
	memcpy(childData, (child->data), child->size);
	parentData = malloc(parent->size + 1);
	memset(parentData, 0x00, (parent->size + 1));
	memcpy(parentData, (parent->data), parent->size);
	d2i_X509(&childCert, &childData, child->size);
	d2i_X509(&parentCert, &parentData, parent->size);
	// check parameter
	//    - 1. if AIA field of cert is exist, use that
	//    - 2. if AIA field of cert is not exist, use uri
	//    - 3. if AIA field of cert is not exist and uri is NULL, fail to check ocsp
	aia = X509_get1_ocsp(childCert);
	if (aia) {
		certAiaUrl = sk_OPENSSL_STRING_value(aia, 0);
	}
	if(uri != NULL) {
		targetUrl = uri;
	}else {
		targetUrl = certAiaUrl;
	}
	if(targetUrl == NULL) {
		SLOGE("[ERR][%s] No URI for OCSP.\n", __func__);
		ret = CERT_SVC_ERR_OCSP_NO_SUPPORT;
		goto err;
	}

	// Load Trusted Store
	systemCerts = sk_X509_new_null();
	ret = __loadSystemCerts(systemCerts) ;
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to extract certificate data\n", __func__);
		goto err;
	}

	// Do OCSP Check
	ret = __ocsp_verify(childCert, parentCert, systemCerts, targetUrl, ocspStatus);
	SLOGD("[%s] OCSP Response. ocspstaus=%d, ret=%d.\n", __func__, *ocspStatus, ret);

err:
	if(childData != NULL && *childData != NULL)
		free(childData);
	if(parentData != NULL && *parentData != NULL)
		free(parentData);
	if(childCert != NULL)
		X509_free(childCert);
	if(parentCert != NULL)
		X509_free(parentCert);
	if(aia != NULL)
		X509_email_free(aia);
	if(systemCerts != NULL) {
		for(i=0; i<sk_X509_num(systemCerts); i++)
			X509_free(sk_X509_value(systemCerts,i));
		sk_X509_free(systemCerts);
	}
	return ret;
}
#endif

int release_certificate_buf(cert_svc_mem_buff* certBuf)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	if(certBuf == NULL)
		return ret;

	if(certBuf->data != NULL) {
		free(certBuf->data);
		certBuf->data = NULL;
	}
	free(certBuf);
	certBuf = NULL;

	return ret;
}

int release_certificate_data(cert_svc_cert_descriptor* certDesc)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	int i = 0;

	if(certDesc == NULL)
		return ret;

	/* parse cert descriptor information fields */
	if(certDesc->info.sigAlgo != NULL) free(certDesc->info.sigAlgo);
	if(certDesc->info.issuerStr != NULL) free(certDesc->info.issuerStr);
	if(certDesc->info.issuer.countryName != NULL) free(certDesc->info.issuer.countryName);
	if(certDesc->info.issuer.localityName != NULL) free(certDesc->info.issuer.localityName);
	if(certDesc->info.issuer.stateOrProvinceName != NULL) free(certDesc->info.issuer.stateOrProvinceName);
	if(certDesc->info.issuer.organizationName != NULL) free(certDesc->info.issuer.organizationName);
	if(certDesc->info.issuer.organizationUnitName != NULL) free(certDesc->info.issuer.organizationUnitName);
	if(certDesc->info.issuer.commonName != NULL) free(certDesc->info.issuer.commonName);
	if(certDesc->info.issuer.emailAddress != NULL) free(certDesc->info.issuer.emailAddress);
	if(certDesc->info.subjectStr != NULL) free(certDesc->info.subjectStr);
	if(certDesc->info.subject.countryName != NULL) free(certDesc->info.subject.countryName);
	if(certDesc->info.subject.localityName != NULL) free(certDesc->info.subject.localityName);
	if(certDesc->info.subject.stateOrProvinceName != NULL) free(certDesc->info.subject.stateOrProvinceName);
	if(certDesc->info.subject.organizationName != NULL) free(certDesc->info.subject.organizationName);
	if(certDesc->info.subject.organizationUnitName != NULL) free(certDesc->info.subject.organizationUnitName);
	if(certDesc->info.subject.commonName != NULL) free(certDesc->info.subject.commonName);
	if(certDesc->info.subject.emailAddress != NULL) free(certDesc->info.subject.emailAddress);
	if(certDesc->info.pubKeyAlgo != NULL) free(certDesc->info.pubKeyAlgo);
	if(certDesc->info.pubKey != NULL) free(certDesc->info.pubKey);
	if(certDesc->info.issuerUID != NULL) free(certDesc->info.issuerUID);
	if(certDesc->info.subjectUID != NULL) free(certDesc->info.subjectUID);

	/* parse cert descriptor extension fields */
	if(certDesc->ext.numOfFields > 0) {
		for(i = 0; i < (int)certDesc->ext.numOfFields; i++) {
			if(certDesc->ext.fields[i].name != NULL) free(certDesc->ext.fields[i].name);
			if(certDesc->ext.fields[i].data != NULL) free(certDesc->ext.fields[i].data);
		}
		if(certDesc->ext.fields != NULL) free(certDesc->ext.fields);
	}

	/* parse signature */
	if(certDesc->signatureAlgo != NULL) free(certDesc->signatureAlgo);
	if(certDesc->signatureData != NULL) free(certDesc->signatureData);

	if(certDesc != NULL) free(certDesc);

	return ret;
}

int release_cert_list(cert_svc_linked_list* certList)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_linked_list* startCert = NULL;
	cert_svc_linked_list* curCert = NULL;

	if(certList == NULL)
		return ret;

	startCert = certList;

	while(1) {
		curCert = startCert;
		startCert = startCert->next;

		if(curCert->certificate != NULL) {
			if(curCert->certificate->data != NULL) {
				free(curCert->certificate->data);
				curCert->certificate->data = NULL;
			}
			free(curCert->certificate);
			curCert->certificate = NULL;
		}

		curCert->next = NULL;

		if(curCert != NULL) {
			free(curCert);
			curCert = NULL;
		}

		if(startCert == NULL)
			break;
	}

	return ret;
}

int release_filename_list(cert_svc_filename_list* fileNames)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_filename_list* startList = NULL;
	cert_svc_filename_list* curList = NULL;

	if(fileNames == NULL)
		return ret;

	startList = fileNames;

	while(1) {
		curList = startList;
		startList = startList->next;

		if(curList->filename != NULL) {
			free(curList->filename);
			curList->filename = NULL;
		}
		curList->next = NULL;
		if(curList != NULL) {
			free(curList);
			curList = NULL;
		}

		if(startList == NULL)
			break;
	}

	return ret;
}


void __print_finger_print(const unsigned char *fingerPrint, unsigned int length)
{
	int i=0;
	char buffer[21] = {0,};

	for(; i<20; i++)
		snprintf(buffer+i, 20, "%0X", fingerPrint[i]);

	SLOGE("FingerPrint : %s", buffer);
}

int get_visibility(CERT_CONTEXT* context, int* visibility)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	unsigned char * cert = NULL;
	int certSize = 0;
	unsigned char *fingerprint = NULL;

	if(!context->certBuf)
	{
		LOGE("certBuf is NULL!");
		return CERT_SVC_ERR_INVALID_PARAMETER;
	}
	if(!context->certBuf->size)
	{
		LOGE("certBuf size is wrong");
		return CERT_SVC_ERR_INVALID_PARAMETER;
	}

	cert = context->certBuf->data;
	certSize = context->certBuf->size;

	if(cert == NULL || !certSize)
	{
		LOGE("cert is or invalid!");
		return CERT_SVC_ERR_INVALID_CERTIFICATE;
	}

	ret = get_certificate_fingerprint(cert, certSize, &fingerprint);
	if(ret != CERT_SVC_ERR_NO_ERROR)
	{
		SLOGE("Failed to get fingerprint data! %d", ret);
		return ret;
	}

	ret = get_visibility_by_fingerprint(fingerprint, visibility);
	if(ret != CERT_SVC_ERR_NO_ERROR)
	{
		SLOGE("Failed to get visibility! %d", ret);
		return ret;
	}

	return CERT_SVC_ERR_NO_ERROR;
}
