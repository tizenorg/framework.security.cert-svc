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
 * @file        SignatureData.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       SignatureData is used to storage data parsed from digsig file.
 */
#include <vcore/SignatureData.h>

#include <dpl/log/log.h>

namespace ValidationCore {

SignatureData::SignatureData()
  : m_signatureNumber(-1)
  , m_certificateSorted(false)
{}

SignatureData::SignatureData(const std::string &fileName, int fileNumber)
  : m_signatureNumber(fileNumber)
  , m_fileName(fileName)
  , m_certificateSorted(false)
{}

SignatureData::~SignatureData()
{}

const ReferenceSet& SignatureData::getReferenceSet() const
{
    return m_referenceSet;
}

void SignatureData::setReference(const ReferenceSet &referenceSet)
{
    m_referenceSet = referenceSet;
}

CertificateList SignatureData::getCertList() const
{
    return m_certList;
}

void SignatureData::setSortedCertificateList(const CertificateList &list)
{
    m_certList = list;
    m_certificateSorted = true;
}

bool SignatureData::isAuthorSignature() const
{
    return m_signatureNumber == -1;
}

std::string SignatureData::getSignatureFileName() const
{
    return m_fileName;
}

int SignatureData::getSignatureNumber() const
{
    return m_signatureNumber;
}

std::string SignatureData::getRoleURI() const
{
    return m_roleURI;
}

std::string SignatureData::getProfileURI() const
{
    return m_profileURI;
}

bool SignatureData::containObjectReference(const std::string &ref) const
{
    std::string rName = "#";
    rName += ref;
    return m_referenceSet.end() != m_referenceSet.find(rName);
}

ObjectList SignatureData::getObjectList() const
{
    return m_objectList;
}

void SignatureData::setStorageType(const CertStoreId::Set &storeIdSet)
{
    m_storeIdSet = storeIdSet;
}

const CertStoreId::Set& SignatureData::getStorageType() const
{
    return m_storeIdSet;
}

const CertStoreId::Type SignatureData::getVisibilityLevel() const
{
    if (m_storeIdSet.contains(CertStoreId::VIS_PLATFORM) == true)
        return CertStoreId::VIS_PLATFORM;
    else if (m_storeIdSet.contains(CertStoreId::VIS_PARTNER_MANUFACTURER) == true)
        return CertStoreId::VIS_PLATFORM;
    else if (m_storeIdSet.contains(CertStoreId::VIS_PARTNER_OPERATOR) == true)
        return CertStoreId::VIS_PLATFORM;
    else if (m_storeIdSet.contains(CertStoreId::VIS_PARTNER) == true)
        return CertStoreId::VIS_PARTNER;
    else if (m_storeIdSet.contains(CertStoreId::VIS_PUBLIC) == true)
        return CertStoreId::VIS_PUBLIC;
    else {
        LogWarning("Visibility level was broken.");
        return 0;
    }
}

const SignatureData::IMEIList& SignatureData::getIMEIList() const
{
    return m_imeiList;
}

const SignatureData::MEIDList& SignatureData::getMEIDList() const
{
    return m_meidList;
}

CertificatePtr SignatureData::getEndEntityCertificatePtr() const
{
    if (m_certificateSorted)
        return m_certList.front();

    return CertificatePtr();
}

CertificatePtr SignatureData::getRootCaCertificatePtr() const
{
    if (m_certificateSorted)
        return m_certList.back();

    return CertificatePtr();
}

} // ValidationCore
