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
 * @file
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief
 */
#ifndef \
    _WRT_ENGINE_SRC_INSTALLER_CORE_VALIDATION_CORE_CERTIFICATEIDENTIFICATOR_H_
#define \
    _WRT_ENGINE_SRC_INSTALLER_CORE_VALIDATION_CORE_CERTIFICATEIDENTIFICATOR_H_

#include <map>

#include <dpl/noncopyable.h>

#include "Certificate.h"
#include "CertStoreType.h"

namespace ValidationCore {
class CertificateIdentifier : public DPL::Noncopyable
{
  public:
    typedef std::map<Certificate::Fingerprint, CertStoreId::Set> FingerPrintMap;

    CertificateIdentifier()
    {
    }
    ~CertificateIdentifier()
    {
    }

    void add(const Certificate::Fingerprint &fingerprint,
            CertStoreId::Type domain)
    {
        fingerPrintMap[fingerprint].add(domain);
    }

    CertStoreId::Set find(const Certificate::Fingerprint &fingerprint) const
    {
        FingerPrintMap::const_iterator iter = fingerPrintMap.find(fingerprint);
        if (iter == fingerPrintMap.end()) {
            return CertStoreId::Set();
        }
        return iter->second;
    }

    CertStoreId::Set find(const CertificatePtr &certificate) const
    {
        return
            find(certificate->getFingerprint(Certificate::FINGERPRINT_SHA1));
    }

  private:
    FingerPrintMap fingerPrintMap;
};
} // namespace ValidationCore

#endif // _WRT_ENGINE_SRC_INSTALLER_CORE_VALIDATION_CORE_CERTIFICATEIDENTIFICATOR_H_
