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
/*
 * @author      Michal Ciepielski(m.ciepielski@samsung.com)
 * @version     0.3
 * @brief
 */

#include <vcore/OCSPCertMgrUtil.h>
#include <vcore/SSLContainers.h>
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
#include <openssl/ocsp.h>
#endif

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <dpl/log/log.h>
#include <dpl/scoped_resource.h>
#include <string.h>
#include <iostream>
#include <string>

#include <cert-service.h>

namespace {
const int MAX_BUF = 1024;

struct ContextDeleter
{
    typedef CERT_CONTEXT* Type;
    static Type NullValue()
    {
        return NULL;
    }
    static void Destroy(Type context)
    {
        if (context) {
            cert_svc_cert_context_final(context);
        }
    }
};
}

namespace ValidationCore {
namespace OCSPCertMgrUtil {
/*
 * TODO This API function should be changed to:
 * CertifiatePtr getCertFromStore(const std::string &subject);
 *
 * All of cert_svc function could return error because input
 * data are corruped. That's why I dont want to throw exceptions
 * in this function.
 */
void getCertFromStore(X509_NAME *subject,
        X509 **xcert)
{
    if (!xcert || *xcert || !subject) {
        LogError("Invalid input!");
        return;
    }

    typedef DPL::ScopedResource<ContextDeleter> ScopedContext;

    int result;
    char buffer[MAX_BUF];
    const unsigned char* ptr = NULL;
    X509 *pCertificate = NULL;
    cert_svc_filename_list *fileList = NULL;

    X509_NAME_oneline(subject, buffer, MAX_BUF);

    ScopedContext ctx(cert_svc_cert_context_init());
    if (ctx.Get() == NULL) {
        LogWarning("Error in cert_svc_cert_context_init.");
        return;
    }

    LogDebug("Search certificate with subject: " << buffer);
    result = cert_svc_search_certificate(ctx.Get(), SUBJECT_STR, buffer);
    LogDebug("Search finished!");

    if (CERT_SVC_ERR_NO_ERROR != result) {
        LogWarning("Error during certificate search");
        return;
    }

    fileList = ctx.Get()->fileNames;

    if (fileList == NULL) {
        LogDebug("No certificate found");
        return;
    }

    if (fileList->filename == NULL) {
        LogWarning("Empty filename");
        return;
    }

    LogDebug("Found cert file: " << fileList->filename);
    ScopedContext ctx2(cert_svc_cert_context_init());

    if (ctx2.Get() == NULL) {
        LogWarning("Error in cert_svc_cert_context_init.");
        return;
    }

    // TODO add read_certifcate_from_file function to Certificate.h
    if (CERT_SVC_ERR_NO_ERROR !=
        cert_svc_load_file_to_context(ctx2.Get(), fileList->filename)) {
        LogWarning("Error in cert_svc_load_file_to_context");
        return;
    }

    ptr = ctx2.Get()->certBuf->data;
    // create a certificate from mem buff
    pCertificate = d2i_X509(NULL, &ptr, ctx2.Get()->certBuf->size);

    if (pCertificate == NULL) {
        LogWarning("Error during certificate conversion in d2i_X509");
        return;
    }

    *xcert = pCertificate;
    if (fileList->next != NULL) {
        LogError("There is more then one certificate with same subject :/");
        // TODO Implement me.
        for (fileList = fileList->next;
             fileList != NULL;
             fileList = fileList->next) {
            LogError(
                "Additional certificate with same subject: " <<
                fileList->filename);
        }
    }
}

CertificatePtr getParentFromStore(const CertificatePtr &certificate)
{
    Assert(certificate.get());
    X509* rawPtr = certificate->getX509();

    /* TODO Add getIssuerName function to Certificate.h */
    X509_NAME *name = X509_get_issuer_name(rawPtr);

    X509* rawTemp = NULL;
    getCertFromStore(name, &rawTemp);

    if (rawTemp == NULL) {
        return CertificatePtr();
    }
    SSLSmartContainer<X509> scope(rawTemp);
    return CertificatePtr(new Certificate(rawTemp));
}

CertificateList completeCertificateChain(const CertificateList &certificateList)
{
    CertificateList result = certificateList;
    CertificatePtr last = result.back();
    if (last->isSignedBy(last)) {
        return result;
    }
    CertificatePtr parent = getParentFromStore(last);
    if (parent.get()) {
        result.push_back(parent);
    }
    return result;
}
} // namespace OCSPCertMgrUtil
} // namespace ValidationCore
