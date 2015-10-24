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
/**
 * @file        cert-svc-client.h
 * @author      Madhan A K (madhan.ak@samsung.com)
 * @version     1.0
 * @brief       cert-svc client interface for cert-svc server present in secure-storage module.
 */

#ifndef CERT_SVC_CLIENT_H_
#define CERT_SVC_CLIENT_H_

#include <cert-svc/cerror.h>
#include <cert-svc/ccert.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VCORE_MAX_FILENAME_SIZE     128
#define VCORE_MAX_RECV_DATA_SIZE    8192    //4096, internal buffer = 4KB*2. /*Note:system store cert size is bigger than 4KB*/
#define VCORE_MAX_SEND_DATA_SIZE    8192    //4096, internal buffer = 4KB*2.
#define VCORE_MAX_GROUP_ID_SIZE     32
#define VCORE_MAX_APPID_SIZE        32
#define VCORE_MAX_PASSWORD_SIZE     32
#define VCORE_SOCKET_ERROR          (-0x01C10000) // TIZEN_ERROR_CONNECTION  /*Connection error*/
#define VCORE_SOCK_PATH             "/tmp/CertSocket"
#define VCORE_PKEY_TEMP_PATH        "/tmp/tmpData"

#define SYSTEM_CERT_DIR             "/opt/etc/ssl/certs/"
#define CERTSVC_PKCS12_STORAGE_DIR  "/opt/share/cert-svc/pkcs12"
#define CERTSVC_SYSTEM_STORE_DB     "/opt/share/cert-svc/dbspace/certs-meta.db"
#define CERTSVC_CRT_FILE_PATH       "/opt/share/ca-certificates/ca-certificate.crt"

typedef enum {
    CERTSVC_EXTRACT_CERT,
    CERTSVC_EXTRACT_SYSTEM_CERT,
    CERTSVC_DELETE_CERT,
    CERTSVC_INSTALL_CERTIFICATE,
    CERTSVC_GET_CERTIFICATE_STATUS,
    CERTSVC_SET_CERTIFICATE_STATUS,
    CERTSVC_CHECK_ALIAS_EXISTS,
    CERTSVC_GET_CERTIFICATE_LIST,
    CERTSVC_GET_CERTIFICATE_ALIAS,
    CERTSVC_GET_USER_CERTIFICATE_LIST,
    CERTSVC_GET_ROOT_CERTIFICATE_LIST,
    CERTSVC_LOAD_CERTIFICATES,
} VcoreRequestType;

typedef struct {
    VcoreRequestType reqType;
    CertStoreType    storeType;
    char             gname[VCORE_MAX_FILENAME_SIZE * 2 + 1]; /* for gname */
    char             common_name[VCORE_MAX_FILENAME_SIZE * 2 + 1]; /* for common_name */
    char             private_key_gname[VCORE_MAX_FILENAME_SIZE * 2 + 1]; /* for private_key_gname */
    char             associated_gname[VCORE_MAX_FILENAME_SIZE * 2 + 1]; /* for associated_gname */
    char             dataBlock[VCORE_MAX_SEND_DATA_SIZE];    /* for cert & key buffer */
    size_t           dataBlockLen;
    int              certStatus;
    int              is_root_app;
    CertType         certType;
} VcoreRequestData;

typedef struct {
    char             gname[VCORE_MAX_FILENAME_SIZE * 2 + 1];
    char             title[VCORE_MAX_FILENAME_SIZE * 2 + 1];
    int              status;
    CertStoreType    storeType;
} VcoreCertResponseData;


typedef struct {
    char             dataBlock[VCORE_MAX_RECV_DATA_SIZE];
    size_t           dataBlockLen;
} ResponseCertBlock;

typedef struct {
    char                   dataBlock[VCORE_MAX_RECV_DATA_SIZE];
    size_t                 dataBlockLen;
    int                    certStatus;
    char                   common_name[VCORE_MAX_FILENAME_SIZE* 2 + 1]; /*for common_name*/
    int                    result;
    int                    certCount;
    VcoreCertResponseData* certList;
    int                    certBlockCount;
    ResponseCertBlock*     certBlockList; // array
} VcoreResponseData;



int vcore_client_set_certificate_status_to_store(CertStoreType storeType, int is_root_app, const char* gname, CertStatus status);
int vcore_client_get_certificate_status_from_store(CertStoreType storeType, const char* gname, int *status);
int vcore_client_check_alias_exist_in_store(CertStoreType storeType, const char* alias, int *status);
int vcore_client_install_certificate_to_store(CertStoreType storeType, const char *gname, const char *common_name, const char *private_key_gname, const char *associated_gname, const char *dataBlock, size_t dataBlockLen, CertType certType);
int vcore_client_get_certificate_from_store(CertStoreType storeType, const char* gname, char** certData, size_t* certSize, CertType certType);
int vcore_client_delete_certificate_from_store(CertStoreType storeType, const char* gname);
VcoreResponseData cert_svc_client_comm(VcoreRequestData* client_data);
int vcore_client_get_certificate_list_from_store(CertStoreType storeType, int is_root_app, CertSvcStoreCertList** certList, int* length);
int vcore_client_get_root_certificate_list_from_store(CertStoreType storeType, CertSvcStoreCertList** certList, int* length);
int vcore_client_get_end_user_certificate_list_from_store(CertStoreType storeType, CertSvcStoreCertList** certList, int* length);
int vcore_client_get_certificate_alias_from_store(CertStoreType storeType, const char *gname, char **alias);
int vcore_client_load_certificates_from_store(CertStoreType storeType, const char *gname, char ***certs, int *ncerts);

#ifdef __cplusplus
}
#endif

#endif
