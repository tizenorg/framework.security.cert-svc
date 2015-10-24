/**
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
/**
 * @file     cert_svc_server_main.h
 * @author   Madhan A K (madhan.ak@samsung.com)
 * @version  1.0
 * @brief    cert-server routines.
 */

#ifndef CERT_SVC_SERVER_MAIN_H_
#define CERT_SVC_SERVER_MAIN_H_

#include <db-util.h>

int getCertificateDetailFromStore(sqlite3 *db_handle, int storeType, int certType, const char* pGname, char* pCertBuffer, size_t *certLength);

int getCertificateDetailFromSystemStore(sqlite3 *db_handle, const char* pGname, char* pCertBuffer, size_t *certLength);

int deleteCertificateFromStore(sqlite3 *db_handle, int storeType, const char* pGname);

int getCertificateStatusFromStore(sqlite3 *db_handle, int storeType, const char* pGname, int *status);

int setCertificateStatusToStore(sqlite3 *db_handle, int storeType, int is_root_app, const char* pGname, int status);

int checkAliasExistsInStore(sqlite3 *db_handle, int storeType, const char* alias, int *status);

int installCertificateToStore(sqlite3 *db_handle, int storeType, const char* pGname, const char *common_name, const char *private_key_gname, const char *associated_gname, const char *pCertBuffer, size_t certLength, int certType);

int getCertificateListFromStore(sqlite3 *db_handle,  int reqType, int storeType, int is_root_app, char **ppCertListBuffer, size_t *bufferLen, int *certCount);

int getCertificateAliasFromStore(sqlite3 *db_handle,  int storeType, const char* pGname, char* alias);

int loadCertificatesFromStore(sqlite3 *db_handle,  int storeType, const char* pGname, char **ppCertBlockBuffer, size_t *bufferLen, int *certBlockCount);

int update_ca_certificate_file(sqlite3 *db_handle, char *certBuffer, size_t certLength);

#endif
