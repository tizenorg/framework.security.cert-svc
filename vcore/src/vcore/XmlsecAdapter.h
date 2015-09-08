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
 * @file        XmlSecAdapter.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief
 */
#ifndef _VALIDATION_CORE_XMLSECADAPTER_H_
#define _VALIDATION_CORE_XMLSECADAPTER_H_

#include <xmlsec/keysmngr.h>

#include <dpl/exception.h>
#include <dpl/noncopyable.h>
#include <dpl/singleton.h>

#include <vcore/Certificate.h>
#include <vcore/SignatureData.h>

namespace ValidationCore {
class XmlSec : public VcoreDPL::Noncopyable
{
  public:

    struct XmlSecContext
    {
        /* You _must_ set one of the value: certificatePath or certificate. */
        XmlSecContext() :
            validationTime(0),
            allowBrokenChain(false),
            errorBrokenChain(false)
        {
        }

        /*
         * Absolute path to signature file.
         */
        std::string signatureFile;
        /*
         * Direcotory with signed data.
         * If you leave it empty xmlsec will use directory extracted
         * from signatureFile.
         */
        std::string workingDirectory;
        /*
         * Path to trusted certificate.
         */
        std::string certificatePath;
        /*
         * Trusted certificate. In most cases it should be Root CA certificate.
         */
        CertificatePtr certificatePtr;
        /*
         * Validation date.
         * 0 - uses current time.
         */
        time_t validationTime;
        /*
         * Input parameter.
         * If true, signature validation will not be interrupted by chain error.
         * If true and chain is broken then the value errorBrokenChain will be
         * set to true.
         */
        bool allowBrokenChain;
        /*
         * Output parameter.
         * This will be set if chain is incomplete or broken.
         */
        bool errorBrokenChain;
        /*
         * Output parameter.
         * Reference checked by xmlsec
         */
        ReferenceSet referenceSet;
    };

    enum Result
    {
        NO_ERROR,
        ERROR_INVALID_SIGNATURE
    };

    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(VcoreDPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, InternalError)
    };

    /*
     * Context - input/output param.
     */
    Result validate(XmlSecContext *context);
    Result validateNoHash(XmlSecContext *context);
    Result validatePartialHash(XmlSecContext *context);
    Result setPartialHashList(const std::list<std::string>& targetUri);
 
 protected:
    XmlSec();
    ~XmlSec();
  private:
    void deinitialize(void);

    void loadDERCertificateMemory(XmlSecContext *context,
            xmlSecKeysMngrPtr mngr);
    void loadPEMCertificateFile(XmlSecContext *context,
            xmlSecKeysMngrPtr mngr);
    Result validateFile(XmlSecContext *context,
            xmlSecKeysMngrPtr mngr);

    bool m_initialized;
    bool m_noHash;
    bool m_partialHash;
    std::list<std::string>* m_pList;

    static std::string s_prefixPath;
    static int fileMatchCallback(const char *filename);
    static void* fileOpenCallback(const char *filename);
    static int fileReadCallback(void *context,
            char *buffer,
            int len);
    static int fileCloseCallback(void *context);
    static void fileExtractPrefix(XmlSecContext *context);
};

typedef VcoreDPL::Singleton<XmlSec> XmlSecSingleton;

} // namespace ValidationCore

#endif // _VALIDATION_CORE_XMLSECVERIFICATOR_H_
