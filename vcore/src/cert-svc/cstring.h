/**
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        cstring.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This is part of C api for ValidationCore.
 */
#ifndef _CERTSVC_CSTRING_H_
#define _CERTSVC_CSTRING_H_

#include <cert-svc/cinstance.h>
#include <cert-svc/cstring.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct CertSvcStringList_t {
    int privateHandler;
    CertSvcInstance privateInstance;
} CertSvcStringList;

typedef struct CertSvcString_t {
    /*
     * You are not allowed to use private fields of this structure. It is internal
     * implementation of strings and it may change at any time without notice!
     * To extract data use certsvc_string_to_cstring function!
     */
    char* privateHandler;
    int privateLength;
    CertSvcInstance privateInstance;
} CertSvcString;

/**
 * This function will duplicate input data. Data in ouput string will be managed by certsvc.
 *
 * @param[in] instance CertSvcString will be conected with this instance.
 * @param[in] input Input data.
 * @param[in] size Input buffer size.
 * @param[out] output Buffer with output data.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_string_new(
    CertSvcInstance instance,
    const char *input,
    int size,
    CertSvcString *output);

/**
 * This function wont duplicate input data. Output param will contain pointer to input
 * so input could not be free as long as ouput param is used.
 *
 * @param[in] instance CertSvcString will be conected with this instance.
 * @param[in] input Input data.
 * @param[in] size Input buffer size.
 * @param[out] output Buffer with output data.
 * @return CERTSVC_SUCCESS, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_string_not_managed(
    CertSvcInstance instance,
    const char *input,
    int size,
    CertSvcString *output);

/**
 * Extract next result from result set. Function certsvc_string_list_free
 * does not free results returned by this function. CertSvcString is valid
 * until certsvc_string_free or vcore_instance_reset or vcore_instance_free
 * is called.
 *
 * @param[in] handler Handler to set of strings.
 * @param[out] buffer The buffer will be pointing to string with distrubution point url or will be set to NULL if error occures.
 * @param[out] size Size of data pointed by buffer or 0 if error occures.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_WRONG_ARGUMENT, CERTSVC_BAD_ALLOC
 */
int certsvc_string_list_get_one(CertSvcStringList hander,
                                int position,
                                CertSvcString *buffer);

/**
 * Extract CertSvcStringList size.
 *
 * @param[in] handler Handler to string list.
 * @param[out] size Number of elements on the list.
 * @return CERTSVC_SUCCESS, CERTSVC_WRONG_ARGUMENT
 */
int certsvc_string_list_get_length(CertSvcStringList hander,int *size);

/**
 * Free data.
 *
 * @param[in] string Data allocated by certsvc_certificate_get_string_field
 */
void certsvc_string_free(CertSvcString string);

/**
 * Free string list.
 *
 * Note: This function does not free strings returned by certsvc_string_list_get_one_result.
 *
 * @param[in] handler String set handler.
 */
void certsvc_string_list_free(CertSvcStringList handler);

/**
 * Convert CertSvcStringPtr into pure c pointer. Please note that this pointer is valid as long as CertSvcString is valid.
 *
 * @param[in] string CertSvcStringPtr.
 * @param[out] buffer cstring
 * @param[out] len Length of cstring
 */
void certsvc_string_to_cstring(CertSvcString string, const char **buffer, int *len);

#ifdef __cplusplus
}
#endif

#endif

