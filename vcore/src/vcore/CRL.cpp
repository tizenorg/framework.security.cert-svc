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
/*!
 * @author      Bartlomiej Grzelewski(b.grzelewski@samsung.com)
 * @version     0.2
 * @file        CRL.cpp
 * @brief       Routines for certificate validation over CRL
 */

#include <vcore/CRL.h>
#include <vcore/CRLImpl.h>

namespace ValidationCore {

CRL::CRL(CRLCacheInterface *ptr)
  : m_impl(new CRLImpl(ptr))
{}

CRL::~CRL() {
    delete m_impl;
}

CRL::RevocationStatus CRL::checkCertificate(const CertificatePtr &argCert) {
    return m_impl->checkCertificate(argCert);
}

CRL::RevocationStatus CRL::checkCertificateChain(
    CertificateCollection certChain)
{
    return m_impl->checkCertificateChain(certChain);
}

VerificationStatus CRL::checkEndEntity(CertificateCollection &chain) {
    return m_impl->checkEndEntity(chain);
}

void CRL::addToStore(const CertificatePtr &argCert) {
    m_impl->addToStore(argCert);
}

bool CRL::updateList(const CertificatePtr &argCert,
                     const UpdatePolicy updatePolicy)
{
    return m_impl->updateList(argCert, updatePolicy);
}

void CRL::addToStore(const CertificateCollection &collection) {
    m_impl->addToStore(collection);
}

bool CRL::updateList(const CertificateCollection &collection,
                     UpdatePolicy updatePolicy)
{
    return m_impl->updateList(collection, updatePolicy);
}

} // namespace ValidationCore
