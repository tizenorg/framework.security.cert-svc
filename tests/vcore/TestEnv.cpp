/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
#include <string>
#include <cstring>
#include <dpl/log/log.h>

#include <cert-service.h>

#include "TestEnv.h"

const char *storePath = "code-signing_wac";

int addCertToStore(const char* name){
    int result = cert_svc_add_certificate_to_store(name, storePath);

    if (CERT_SVC_ERR_NO_ERROR != result) {
        LogError("Error adding certificate: " << name << " To: " << storePath);
    }
    return result;
}

//long int removeCertFromStore(const char* subjectName, const char* issuerName)
//{
//    long int result = OPERATION_SUCCESS;
//    /*  Retrieve all the certificates from store */
//    certmgr_cert_id certId;
//    certmgr_mem_buff certRetrieved;
//    certmgr_ctx context;
//    char storeId[CERTMGR_MAX_PLUGIN_ID_SIZE];
//    char type[CERTMGR_MAX_CERT_TYPE_SIZE];
//    unsigned char certBuff[CERTMGR_MAX_BUFFER_SIZE * 2];
//
//    certmgr_cert_descriptor descriptor;
//    certId.storeId = storeId;
//    certId.type = type;
//
//    CERTMGR_INIT_CONTEXT((&context), (sizeof(certmgr_ctx)))
//    std::string storeName("Operator");
//    strncpy(context.storeId, storeName.c_str(), storeName.size());
//
//    certRetrieved.data = certBuff;
//    certRetrieved.size = CERTMGR_MAX_BUFFER_SIZE * 2;
//
//    certRetrieved.firstFree = 0;
//
//    for(certRetrieved.firstFree = 0;
//      OPERATION_SUCCESS ==
//      (result = certmgr_retrieve_certificate_from_store( &context, &certRetrieved, &certId));
//      certRetrieved.firstFree = 0)
//    {
//        if(OPERATION_SUCCESS ==
//          certmgr_extract_certificate_data(&certRetrieved, &descriptor)){
//            LogDebug("The subject of this certificate is " << descriptor.mandatory.subject);
//            LogDebug("The issuer of this certificate is " << descriptor.mandatory.issuer);
//        }
//
//        if(strcmp(descriptor.mandatory.subject, subjectName) == 0 &&
//          strcmp(descriptor.mandatory.issuer,issuerName) == 0    &&
//          OPERATION_SUCCESS == certmgr_remove_certificate_from_store(&certId))
//        {
//            LogDebug("***Certificate has been REMOVED***");
//            return OPERATION_SUCCESS;
//        }
//    }
//
//    if(ERR_NO_MORE_CERTIFICATES == result){
//        LogDebug("***THIS CERT IS NOT IN STORE***");
//        return OPERATION_SUCCESS;
//    }
//
//    return result;
//}

int removeCertGivenByFilename(const char* name){
    int result = cert_svc_delete_certificate_from_store(name, storePath);

    if (CERT_SVC_ERR_NO_ERROR != result) {
        LogError("Error removing certificate: " << name << " From: " << storePath);
    }

    return result;
}

