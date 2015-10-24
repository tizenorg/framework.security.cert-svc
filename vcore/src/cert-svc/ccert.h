/**
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
/*
 * @file        ccert.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This is part of C api for ValidationCore.
 */
#ifndef _CERTSVC_CCERT_H_
#define _CERTSVC_CCERT_H_

#include <time.h>

#include <cert-svc/cinstance.h>
#include <cert-svc/cstring.h>

#ifndef TIZEN_FEATURE_CERT_SVC_STORE_CAPABILITY
#define TIZEN_FEATURE_CERT_SVC_STORE_CAPABILITY
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CertSvcCertificate_t {
    int privateHandler;
    CertSvcInstance privateInstance;
} CertSvcCertificate;

typedef struct CertSvcCertificateList_t {
    int privateHandler;
    CertSvcInstance privateInstance;
} CertSvcCertificateList;

#ifdef TIZEN_FEATURE_CERT_SVC_STORE_CAPABILITY
/* Update the MAX_STORE_ENUMS whenever the list is updated */
#define MAX_STORE_ENUMS 5
typedef enum certImportType_t {
    VPN_STORE    =  1 << 0,
    WIFI_STORE   =  1 << 1,
    EMAIL_STORE  =  1 << 2,
    SYSTEM_STORE =  1 << 3,
    ALL_STORE    =  VPN_STORE | WIFI_STORE | EMAIL_STORE | SYSTEM_STORE
} CertStoreType;

typedef struct CertSvcStoreCertList_t{
    char* gname;             // keyfile group name
    char* title;             // common Name / Alias provided by the user
    int status;              // enabled / disabled
    CertStoreType storeType; // Holds the storetype information
    struct CertSvcStoreCertList_t *next;
}CertSvcStoreCertList;

typedef enum certType_t {
    PEM_CRT          = 1 << 0,
    P12_END_USER     = 1 << 1,
    P12_INTERMEDIATE = 1 << 2,
    P12_TRUSTED      = 1 << 3,
    P12_PKEY         = 1 << 4,
    INVALID_DATA     = 1 << 5,
} CertType;

typedef enum certStatus_t {
    DISABLED     =  0,
    ENABLED      =  1,
} CertStatus;
#else
typedef struct CertSvcStoreCertList_t{
    char* gname;   // keyfile group name
    char* title;   // common Name
    char* path;    // absolute path
    struct CertSvcStoreCertList_t *next;
}CertSvcStoreCertList;
#endif

typedef enum CertSvcCertificateForm_t {
/*    CERTSVC_FORM_PEM, */
    CERTSVC_FORM_DER,
    CERTSVC_FORM_DER_BASE64
} CertSvcCertificateForm;

typedef enum CertSvcCertificateField_t {
    CERTSVC_SUBJECT,
    CERTSVC_SUBJECT_COMMON_NAME,
    CERTSVC_SUBJECT_COUNTRY_NAME,
    CERTSVC_SUBJECT_STATE_NAME,
    CERTSVC_SUBJECT_ORGANIZATION_NAME,
    CERTSVC_SUBJECT_ORGANIZATION_UNIT_NAME,
    CERTSVC_SUBJECT_EMAIL_ADDRESS,
    CERTSVC_ISSUER,
    CERTSVC_ISSUER_COMMON_NAME,
    CERTSVC_ISSUER_COUNTRY_NAME,
    CERTSVC_ISSUER_STATE_NAME,
    CERTSVC_ISSUER_ORGANIZATION_NAME,
    CERTSVC_ISSUER_ORGANIZATION_UNIT_NAME,
    CERTSVC_VERSION,
    CERTSVC_SERIAL_NUMBER,
    CERTSVC_KEY_USAGE,
    CERTSVC_KEY,
    CERTSVC_SIGNATURE_ALGORITHM
} CertSvcCertificateField;

typedef enum CertSvcVisibility_t {
	CERTSVC_VISIBILITY_DEVELOPER = 1,
	CERTSVC_VISIBILITY_TEST = 1 << 1,
	CERTSVC_VISIBILITY_PUBLIC = 1 << 6,
	CERTSVC_VISIBILITY_PARTNER = 1 << 7,
	CERTSVC_VISIBILITY_PARTNER_OPERATOR = 1 << 8,
	CERTSVC_VISIBILITY_PARTNER_MANUFACTURER = 1 << 9,
	CERTSVC_VISIBILITY_PLATFORM = 1 << 10
} CertSvcVisibility;

#ifdef TIZEN_FEATURE_CERT_SVC_STORE_CAPABILITY
/**
 * This function will return certificate for the unique name identifier passed (gname).
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] storeType Refers to the store (WIFI_STORE, VPN_STORE, EMAIL_STORE, SSL_STORE).
 * @oaran[in] gname Refers to the unique name identifier associated for the certificate.
 * @param[out] certificate Certificate for the gname passed.
 * @return CERTSVC_SUCCESS, CERTSVC_BAD_ALLOC, CERTSVC_FAIL, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_get_certificate(CertSvcInstance instance,
                            CertStoreType storeType,
                            char *gname,
                            CertSvcCertificate *certificate);
#endif
/**
 * Read certificate from file. Certificate must be in PEM/CER/DER format.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] location Path to file with certificate file.
 * @param[out] certificate Certificate id assigned to loaded certificate.
 * @return CERTSVC_SUCCESS, CERTSVC_BAD_ALLOC, CERTSVC_FAIL, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_certificate_new_from_file(CertSvcInstance instance,
                                      const char *location,
                                      CertSvcCertificate *certificate);

/**
 * Read certificate stored in memory.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] memory Pointer to memory with certificate data.
 * @param[in] len Size of certificate.
 * @param[in] form Certificate format.
 * @param[out] certificate Certificate id assigned to loaded certificate.
 * @return CERTSVC_SUCCESS, CERTSVC_BAD_ALLOC, CERTSVC_FAIL
 */
int certsvc_certificate_new_from_memory(CertSvcInstance instance,
                                        const unsigned char *memory,
                                        int len,
                                        CertSvcCertificateForm form,
                                        CertSvcCertificate *certificate);

/**
 * Free structures connected with certificate.
 *
 * @param[in] certificate Certificate id.
 */
void certsvc_certificate_free(CertSvcCertificate certificate);

/**
 * Save certificate to file. It saves certificate in DER format.
 *
 * @param[in] certificate Certificate id.
 * @param[in] location Path to file.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_certificate_save_file(CertSvcCertificate certificate, const char *location);

/**
 * Search certificate with specific data. Result is stored in CertSvcInstance.
 * This function will erase all preverious results stored in CertSvcInstance but
 * it will not erase any CertSvcCertificate.
 *
 * You can search by fields: CERTSVC_SUBJECT, CERTSVC_ISSUER, CERTSVC_SUBJECT_COMMON_NAME
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] field Certificate filed name.
 * @param[in] value Value to search for.
 * @param[out] handler Handler to search result.
 * @return CERTSVC_SUCCESS, CERTSVC_BAD_ALLOC, CERTSVC_FAIL, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_certificate_search(CertSvcInstance instance,
                               CertSvcCertificateField field,
                               const char *value,
                               CertSvcCertificateList *handler);

/**
 * This function will return certificate id founded by certsvc_certificate_search.
 * You can call this function multiple times to get all results.
 *
 * @param[in] hadler Hander to search results.
 * @param[in] position
 * @param[out] certificate Certficate id.
 * @return CERTSVC_SUCCESS, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_certificate_list_get_one(CertSvcCertificateList handler,
                                     int position,
                                     CertSvcCertificate *certificate);

/**
 * Return number of elements on the list.
 *
 * @param[in] handler Handler to certifiacte list.
 * @param[out] length Size of list.
 * @return CERTSVC_SUCCESS, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_certificate_list_get_length(CertSvcCertificateList handler,
                                        int *size);

/**
 * This function will free list. It will not free certificates on the list.
 * You may free each certificate with certsvc_certificate_free.
 *
 * @param[in] handler Handler to search result.
 */
void certsvc_certificate_list_free(CertSvcCertificateList handler);

/**
 * Compare parent certificate subject with child issuer field.
 *
 * @param[in] child
 * @param[in] parent
 * @param[out] status CERTSVC_TRUE if "signer" was used to sign "child" certificate in other cases it will return CERTSVC_FALSE.
 * @return CERTSVC_SUCCESS, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_certificate_is_signed_by(CertSvcCertificate child,
                                     CertSvcCertificate parent,
                                     int *status);

/**
 * Extract specific data from certificate. Data in buffer could be free
 * by certsvc_free_string function or by
 * certsvc_instance_free or vcore_instance_reset.
 *
 * @param[in] certificate Certificate id.
 * @param[in] field Type of data to extract.
 * @param[out] buffer Extracted data.
 * return CERTSVC_SUCCESS, CERTSVC_BAD_ALLOC, CERTSVC_FAIL
 */
int certsvc_certificate_get_string_field(CertSvcCertificate certificate,
                                         CertSvcCertificateField field,
                                         CertSvcString *buffer);

/**
 * Extract NOT AFTER data from certificate.
 *
 * @param[in] certificate Certificate id.
 * @param[out] result date
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_certificate_get_not_after(CertSvcCertificate certificate, time_t *result);

/**
 * Extract NOT AFTER data from certificate.
 *
 * @param[in] certificate Certificate id.
 * @param[out] result date
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_certificate_get_not_before(CertSvcCertificate certificate, time_t *result);

/**
 * Check certificate. This fuction compares SUBJECT and ISSUER fields.
 * TODO: This fuction should also check ROOTCA field in certificate.
 *
 * @param[in] certificate Certificate id.
 * @param[out] status CERTSVC_TRUE or CERTSVC_FALSE
 * @return CERTSVC_SUCCESS, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_certificate_is_root_ca(CertSvcCertificate certificate, int *status);

/**
 * Extract all distribution point from certificate.
 *
 * @param[in] certificate Certificate with distribution points.
 * @param[out] hander Handler to set of string.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_WRONG_ARGUMENT
 *
 * Usage example:
 *
 * int max;
 * CertSvcStringList handler;
 * certsvc_certificate_get_crl_distribution_points(instance, some_certificate, &handler);
 * certsvc_certificate_list_get_length(handler, &max);
 * for(int i=0; i<max; ++i)
 *   char *buffer;
 *   int len;
 *   CertSvcString string;
 *   certsvc_string_list_get_one(handler, i, &string);
 *   printf("%s\n", buffer);
 *   certsvc_string_free(buffer); // optional
 * }
 * certsvc_string_list_free(handler); // optional
 */
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
int certsvc_certificate_get_crl_distribution_points(CertSvcCertificate certificate,
                                                    CertSvcStringList *handler);
#endif

/**
 * Sort certificates chain. This fuction modifies certificate_array.
 *
 * If function success:
 *  * certificate array will contain end entity certificate as first element
 *  * last element on the certificate_array will contain Root CA certificate or
 *    CA certificate (if Root CA is not present).
 *
 * @param[in/out] certificate_array
 * @param[in] size Size of certificate_array
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_WRONG_ARGUMENT, CERTSVC_BAD_ALLOC
 */
int certsvc_certificate_chain_sort(CertSvcCertificate *unsortedChain, int size);

/**
 * Base64 string will be connected with same instance as message.
 * You can free base64 string with certsvc_string_free (or certsvc_instance_reset).
 *
 * @param[in] message Buffer with input data.
 * @param[out] base64 Buffer with output data.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_base64_encode(CertSvcString message, CertSvcString *base64);

/**
 * Message string will be connected with same certsvc instance as base64.
 * You can free base64 string with certsvc_string_free (or certsvc_instance_reset).
 *
 * @param[in] base64 Buffer with input data.
 * @param[out] message Buffer with output data.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_base64_decode(CertSvcString base64, CertSvcString *message);

/**
 * Use certificate to verify message.
 *
 * @param[in] certificate
 * @param[in] message
 * @param[in] algorithm May be set to NULL.
 * @param[out] status Will be set only if function return CERTSVC_SUCCESS.
 *                    It could be set to: CERTSVC_SUCCESS, CERTSVC_INVALID_SIGNATURE
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_WRONG_ARGUMENT, CERTSVC_INVALID_ALGORITHM
 */
int certsvc_message_verify(
    CertSvcCertificate certificate,
    CertSvcString message,
    CertSvcString signature,
    const char *algorithm,
    int *status);

/**
 * This function will create full chain and verify in.
 *
 * First argument of function will be treatet as endentity certificate.
 *
 * This function will success if root CA certificate is stored in
 * trusted array.
 *
 * @param[in] certificate Certificate to verify.
 * @param[in] trusted Array with trusted certificates.
 * @param[in] trustedSize Number of trusted certificates in array.
 * @param[in] untrusted Array with untrusted certificates.
 * @param[in] untrustedSize Number of untrusted certificate in array.
 * @param[out] status Will be set only if function return CERTSVC_SUCCESS.
 *                    It could be set to: CERTSVC_SUCCESS, CERTSVC_FAIL
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_certificate_verify(
    CertSvcCertificate certificate,
    CertSvcCertificate *trusted,
    int trustedSize,
    CertSvcCertificate *untrusted,
    int untrustedSize,
    int *status);

/**
 * This function will create full chain and verify in.
 * And this function checks the CA Flag strictly.
 *
 * First argument of function will be treatet as endentity certificate.
 *
 * This function will success if root CA certificate is stored in
 * trusted array.
 *
 * @param[in] certificate Certificate to verify.
 * @param[in] trusted Array with trusted certificates.
 * @param[in] trustedSize Number of trusted certificates in array.
 * @param[in] untrusted Array with untrusted certificates.
 * @param[in] untrustedSize Number of untrusted certificate in array.
 * @param[out] status Will be set only if function return CERTSVC_SUCCESS.
 *                    It could be set to: CERTSVC_SUCCESS, CERTSVC_FAIL
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_certificate_verify_with_caflag(
	    CertSvcCertificate certificate,
	    CertSvcCertificate *trusted,
	    int trustedSize,
	    CertSvcCertificate *untrusted,
	    int untrustedSize,
	    int *status);

/**
 * This function returns visibility of input certificate.
 *
 * @param[in] The root certificate to check visibility.
 * @param[out] Visibility level
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR
 *
 */
int certsvc_certificate_get_visibility(CertSvcCertificate certificate, int* visibility);


#ifdef __cplusplus
}
#endif

#endif

