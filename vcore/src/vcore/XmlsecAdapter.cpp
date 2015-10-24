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
 * @file        XmlsecAdapter.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief
 */
#include <cstdlib>
#include <cstring>

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#endif /*   XMLSEC_NO_XSLT */

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/crypto.h>
#include <xmlsec/io.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/errors.h>

#include <dpl/assert.h>
#include <dpl/log/wrt_log.h>

#include <vcore/XmlsecAdapter.h>

#include <vcore/ValidatorCommon.h>

#include <dpl/singleton_impl.h>
IMPLEMENT_SINGLETON(ValidationCore::XmlSec)

namespace {

struct FileWrapper {
    FileWrapper(void *argFile, bool argReleased)
      : file(argFile)
      , released(argReleased)
    {}
    void *file;
    bool released;
};

} // anonymous namespace

namespace ValidationCore {
VC_DECLARE_DELETER(xmlSecKeysMngr, xmlSecKeysMngrDestroy)

static const char* DIGEST_MD5 = "md5";

std::string XmlSec::s_prefixPath;

int XmlSec::fileMatchCallback(const char *filename)
{
    std::string path = s_prefixPath + filename;
    return xmlFileMatch(path.c_str());
}

void* XmlSec::fileOpenCallback(const char *filename)
{
    std::string path = s_prefixPath + filename;

   // WrtLogD("Xmlsec opening: %s", path);
    return new FileWrapper(xmlFileOpen(path.c_str()),false);
}

int XmlSec::fileReadCallback(void *context,
        char *buffer,
        int len)
{
    FileWrapper *fw = static_cast<FileWrapper*>(context);
    if (fw->released) {
        return 0;
    }
    int output = xmlFileRead(fw->file, buffer, len);
    if (output == 0) {
        fw->released = true;
        xmlFileClose(fw->file);
    }
    return output;
}

int XmlSec::fileCloseCallback(void *context)
{
  //WrtLogD("Xmlsec closing:  ");
    FileWrapper *fw = static_cast<FileWrapper*>(context);
    int output = 0;
    if (!(fw->released)) {
        output = xmlFileClose(fw->file);
    }
    delete fw;
    return output;
}

void XmlSec::fileExtractPrefix(XmlSecContext *context)
{
    if (!(context->workingDirectory.empty())) {
        s_prefixPath = context->workingDirectory;
        return;
    }

    s_prefixPath = context->signatureFile;
    size_t pos = s_prefixPath.rfind('/');
    if (pos == std::string::npos) {
        s_prefixPath.clear();
    } else {
        s_prefixPath.erase(pos + 1, std::string::npos);
    }
}

void LogDebugPrint(const char* file, int line, const char* func, 
       const char* errorObject, const char* errorSubject, 
       int reason, const char* msg)
{
    char total[1024];
    snprintf(total, sizeof(total), "[%s:%d][%s] : [%s] : [%s] : [%s]", file, line, func, errorObject, errorSubject, msg);

    if(reason != 256)
    {
       fprintf(stderr, "## [validate error]: %s\n", total);
       WrtLogE(" %s", total);
    }
    else
    {
       WrtLogD(" %s", total);
    }
}

XmlSec::XmlSec() :
    m_initialized(false),
    m_noHash(false),
    m_partialHash(false),
    m_pList(NULL)
{
    LIBXML_TEST_VERSION
        xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);
#ifndef XMLSEC_NO_XSLT
    xmlIndentTreeOutput = 1;
#endif

    if (xmlSecInit() < 0) {
        WrtLogE("Xmlsec initialization failed.");
        ThrowMsg(Exception::InternalError, "Xmlsec initialization failed.");
    }

    if (xmlSecCheckVersion() != 1) {
        xmlSecShutdown();
        WrtLogE("Loaded xmlsec library version is not compatible.");
        ThrowMsg(Exception::InternalError,
                 "Loaded xmlsec library version is not compatible.");
    }

#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
    if (xmlSecCryptoDLLoadLibrary(BAD_CAST XMLSEC_CRYPTO) < 0) {
        xmlSecShutdown();
        WrtLogE(
            "Error: unable to load default xmlsec-crypto library. Make sure "
            "that you have it installed and check shared libraries path "
            "(LD_LIBRARY_PATH) envornment variable.");
        ThrowMsg(Exception::InternalError,
                 "Unable to load default xmlsec-crypto library.");
    }
#endif

    if (xmlSecCryptoAppInit(NULL) < 0) {
        xmlSecShutdown();
        WrtLogE("Crypto initialization failed.");
        ThrowMsg(Exception::InternalError, "Crypto initialization failed.");
    }

    if (xmlSecCryptoInit() < 0) {
        xmlSecCryptoAppShutdown();
        xmlSecShutdown();
        WrtLogE("Xmlsec-crypto initialization failed.");
        ThrowMsg(Exception::InternalError,
                 "Xmlsec-crypto initialization failed.");
    }

    m_initialized = true;
}

void XmlSec::deinitialize(void)
{
    Assert(m_initialized);

    /*   Shutdown xmlsec-crypto library */
    xmlSecCryptoShutdown();

    /*   Shutdown crypto library */
    xmlSecCryptoAppShutdown();

    /*   Shutdown xmlsec library */
    xmlSecShutdown();

    /*   Shutdown libxslt/libxml */
#ifndef XMLSEC_NO_XSLT
    xsltCleanupGlobals();
#endif /*   XMLSEC_NO_XSLT */

    s_prefixPath.clear();
    m_initialized = false;
}

XmlSec::~XmlSec()
{
   m_noHash= false;
   m_partialHash = false;
    if (m_initialized) {
        deinitialize();
    }
}

XmlSec::Result XmlSec::validateFile(XmlSecContext *context,
        xmlSecKeysMngrPtr mngr)
{
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    int size, res = -1;

    fileExtractPrefix(context);
    WrtLogD("Prefix path: %s", s_prefixPath.c_str());

    xmlSecIOCleanupCallbacks();

    xmlSecIORegisterCallbacks(
        fileMatchCallback,
        fileOpenCallback,
        fileReadCallback,
        fileCloseCallback);

    /*   load file */
    doc = xmlParseFile(context->signatureFile.c_str());
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)) {
        WrtLogW("Unable to parse file %s", (context->signatureFile).c_str());
        goto done;
    }

    /*   find start node */
    node = xmlSecFindNode(xmlDocGetRootElement(
                              doc), xmlSecNodeSignature, xmlSecDSigNs);
    if (node == NULL) {
        WrtLogW("Start node not found in %s", (context->signatureFile).c_str());
        goto done;
    }

    /*   create signature context */
    dsigCtx = xmlSecDSigCtxCreate(mngr);
    if (dsigCtx == NULL) {
        WrtLogE("Failed to create signature context.");
        goto done;
    }

    if (context->allowBrokenChain) {
        dsigCtx->keyInfoReadCtx.flags |=
            XMLSEC_KEYINFO_FLAGS_ALLOW_BROKEN_CHAIN;
    }

    if (context->validationTime) {
        WrtLogD("Setting validation time.");
        dsigCtx->keyInfoReadCtx.certsVerificationTime = context->validationTime;
    }

    if( m_noHash == true || m_partialHash == true ) {
        WrtLogD("SignatureEx start >> ");
        if( m_pList == NULL ) {
            WrtLogW("## [validate]: uriList does not exist" );
            fprintf(stderr, "## [validate]: uriList does not exist\n");
            res = xmlSecDSigCtxVerifyEx(dsigCtx, node, 1, NULL);
    } else {
        int n = 0;
        int i = 0;

        if(m_pList == NULL)
        {
          WrtLogW("## [validate]: uriList does not exist" );
          fprintf(stderr, "## [validate]: uriList does not exist\n");
          res = -1;
          goto done;
        }

        n = m_pList->size();

        char* pList[n + 1];
        std::list<std::string>::const_iterator itr = m_pList->begin();
        std::string tmpString;
        char* uri = NULL;
        int len;

        for(; itr != m_pList->end(); ++itr) {
           tmpString = (*itr);
           uri = (char*)tmpString.c_str();
           len = strlen(uri);
           pList[i] = (char*)malloc(len + 1);
           memcpy(pList[i], uri, len);
           pList[i][len] = '\0';
           fprintf(stderr, "## [validate]: uriList[%d] = %s\n", i, pList[i]);
           ++i;
        }
        pList[n] = '\0';

        res = xmlSecDSigCtxVerifyEx(dsigCtx, node, 0, (void*)pList);
        i = 0;
        while(pList[i] != NULL) {
          free(pList[i]);
          ++i;
        }
     }

     if(res < 0) {
        WrtLogE("SignatureEx verify error.");
        fprintf(stderr, "## [validate error]: SignatureEx verify error\n");
        res = -1;
        goto done;
     }
    } else {
       WrtLogD("Signature start >> ");

       /*  Verify signature */
       if (xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
         WrtLogE("Signature verify error.");
         fprintf(stderr, "## [validate error]: Signature verify error\n");
         res = -1;
         goto done;
      }
    }

    if (dsigCtx->keyInfoReadCtx.flags2 &
     XMLSEC_KEYINFO_ERROR_FLAGS_BROKEN_CHAIN) {
        WrtLogW("XMLSEC_KEYINFO_FLAGS_ALLOW_BROKEN_CHAIN was set to true!");
        WrtLogW("Signature contains broken chain!");
        context->errorBrokenChain = true;
    }

    /*   print verification result to stdout */
    if (dsigCtx->status == xmlSecDSigStatusSucceeded) {
        WrtLogD("Signature is OK");
        res = 0;
    } else {
        WrtLogD("Signature is INVALID");
        res = -1;
        goto done;
    }

    if (dsigCtx->c14nMethod && dsigCtx->c14nMethod->id &&
        dsigCtx->c14nMethod->id->name) {
       // WrtLogI("Canonicalization method: %s", (reinterpret_cast<const char *>(dsigCtx->c14nMethod->id->name)).c_str());
    }

    size = xmlSecPtrListGetSize(&(dsigCtx->signedInfoReferences));
    for (int i = 0; i < size; ++i) {
        xmlSecDSigReferenceCtxPtr dsigRefCtx =
            (xmlSecDSigReferenceCtxPtr)xmlSecPtrListGetItem(&(dsigCtx->
                                                                  signedInfoReferences),
                                                            i);
        if (dsigRefCtx && dsigRefCtx->uri) {
            if (dsigRefCtx->digestMethod && dsigRefCtx->digestMethod->id &&
                dsigRefCtx->digestMethod->id->name) {
                const char* pDigest =
                    reinterpret_cast<const char *>(dsigRefCtx->digestMethod->id
                                                       ->name);
                std::string strDigest(pDigest);
                /*WrtLogI("reference digest method: %s" (reinterpret_cast<const char *>(dsigRefCtx->digestMethod->id->name)).c_str());*/
                if (strDigest == DIGEST_MD5) {
                    WrtLogW("MD5 digest method used! Please use sha");
                    res = -1;
                    break;
                }
            }
            context->referenceSet.insert(std::string(reinterpret_cast<char *>(
                                                         dsigRefCtx->uri)));
        }
    }

done:
    m_pList = NULL;
    m_noHash = false;
    m_partialHash = false;

    /*   cleanup */
    if (dsigCtx != NULL) {
        xmlSecDSigCtxDestroy(dsigCtx);
    }

    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    if (res) {
        return ERROR_INVALID_SIGNATURE;
    }
    return NO_ERROR;
}

void XmlSec::loadDERCertificateMemory(XmlSecContext *context,
        xmlSecKeysMngrPtr mngr)
{
    unsigned char *derCertificate = NULL;
    int size = i2d_X509(context->certificatePtr->getX509(), &derCertificate);

    if (!derCertificate) {
        WrtLogE("Failed during x509 conversion to der format.");
        ThrowMsg(Exception::InternalError,
                 "Failed during x509 conversion to der format.");
    }

    if (xmlSecCryptoAppKeysMngrCertLoadMemory(mngr,
                                              derCertificate,
                                              size,
                                              xmlSecKeyDataFormatDer,
                                              xmlSecKeyDataTypeTrusted) < 0) {
        OPENSSL_free(derCertificate);
        WrtLogE("Failed to load der certificate from memory.");
        ThrowMsg(Exception::InternalError,
                 "Failed to load der certificate from memory.");
    }

    OPENSSL_free(derCertificate);
}

void XmlSec::loadPEMCertificateFile(XmlSecContext *context,
        xmlSecKeysMngrPtr mngr)
{
    if (xmlSecCryptoAppKeysMngrCertLoad(mngr,
                                        context->certificatePath.c_str(),
                                        xmlSecKeyDataFormatPem,
                                        xmlSecKeyDataTypeTrusted) < 0) {
        WrtLogE("Failed to load PEM certificate from file.");
        ThrowMsg(Exception::InternalError,
                 "Failed to load PEM certificate from file.");
    }
}

XmlSec::Result XmlSec::validate(XmlSecContext *context)
{
    Assert(context);
    Assert(!(context->signatureFile.empty()));
    Assert(context->certificatePtr.get() || !(context->certificatePath.empty()));

    xmlSecErrorsSetCallback(LogDebugPrint);

    if (!m_initialized) {
        WrtLogE("XmlSec is not initialized.");
        ThrowMsg(Exception::InternalError, "XmlSec is not initialized");
    }

    AutoPtr<xmlSecKeysMngr> mngr(xmlSecKeysMngrCreate());

    if (!mngr.get()) {
        WrtLogE("Failed to create keys manager.");
        ThrowMsg(Exception::InternalError, "Failed to create keys manager.");
    }

    if (xmlSecCryptoAppDefaultKeysMngrInit(mngr.get()) < 0) {
        WrtLogE("Failed to initialize keys manager.");
        ThrowMsg(Exception::InternalError, "Failed to initialize keys manager.");
    }
    context->referenceSet.clear();

    if (context->certificatePtr.get()) {
        loadDERCertificateMemory(context, mngr.get());
    }

    if (!context->certificatePath.empty()) {
        loadPEMCertificateFile(context, mngr.get());
    }

    return validateFile(context, mngr.get());
}

XmlSec::Result XmlSec::validateNoHash(XmlSecContext *context)
{
    xmlSecErrorsSetCallback(LogDebugPrint);

    m_noHash = true;
    return validate(context);
}

XmlSec::Result XmlSec::validatePartialHash(XmlSecContext *context)
{
    xmlSecErrorsSetCallback(LogDebugPrint);

    m_partialHash = true;
    return validate(context);
}

XmlSec::Result XmlSec::setPartialHashList(const std::list<std::string>& targetUri)
{
  xmlSecErrorsSetCallback(LogDebugPrint);

    m_pList = (std::list<std::string>*)&targetUri;
    return NO_ERROR;
}
} // namespace ValidationCore
