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
 * @file        CertificateCollection.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     0.1
 * @brief
 */
#include <vcore/CertificateCollection.h>

#include <algorithm>

#include <dpl/binary_queue.h>
#include <dpl/foreach.h>
#include <dpl/log/log.h>

#include <vcore/Base64.h>

namespace {

using namespace ValidationCore;

inline std::string toBinaryString(int data)
{
    char buffer[sizeof(int)];
    memcpy(buffer, &data, sizeof(int));
	return std::string(buffer, sizeof(int));
}

} // namespace

namespace ValidationCore {

CertificateCollection::CertificateCollection()
  : m_collectionStatus(COLLECTION_UNSORTED)
{}

void CertificateCollection::clear(void)
{
    m_collectionStatus = COLLECTION_UNSORTED;
    m_certList.clear();
}

void CertificateCollection::load(const CertificateList &certList)
{
    m_collectionStatus = COLLECTION_UNSORTED;
    std::copy(certList.begin(),
              certList.end(),
              std::back_inserter(m_certList));
}

bool CertificateCollection::load(const std::string &buffer)
{
    Base64Decoder base64;
    base64.reset();
    base64.append(buffer);
    if (!base64.finalize()) {
        LogWarning("Error during chain decoding");
        return false;
    }
    std::string binaryData = base64.get();

    DPL::BinaryQueue queue;
    queue.AppendCopy(binaryData.c_str(), binaryData.size());

    int certNum;
    queue.FlattenConsume(&certNum, sizeof(int));

    CertificateList list;

    for (int i = 0; i < certNum; ++i) {
        int certSize;
        queue.FlattenConsume(&certSize, sizeof(int));
        std::vector<char> rawDERCert;
        rawDERCert.resize(certSize);
        queue.FlattenConsume(&rawDERCert[0], certSize);
        Try {
            list.push_back(CertificatePtr(
                               new Certificate(std::string(rawDERCert.begin(),
                                                           rawDERCert.end()))));
        } Catch(Certificate::Exception::Base) {
            LogWarning("Error during certificate creation.");
            return false;
        }
        LogDebug("Loading certificate. Certificate common name: " <<
                 list.back()->getCommonName());
    }
    load(list);
    return true;
}

std::string CertificateCollection::toBase64String() const
{
    std::ostringstream output;
    int certNum = m_certList.size();
    output << toBinaryString(certNum);
    FOREACH(i, m_certList){
        std::string derCert = (*i)->getDER();
        output << toBinaryString(derCert.size());
        output << derCert;
    }
    Base64Encoder base64;
    base64.reset();
    base64.append(output.str());
    base64.finalize();
    return base64.get();
}

CertificateList CertificateCollection::getCertificateList() const
{
    return m_certList;
}

bool CertificateCollection::isChain() const
{
    if (COLLECTION_SORTED != m_collectionStatus) {
        LogError("You must sort certificates first");
        ThrowMsg(Exception::WrongUsage,
                 "You must sort certificates first");
    }
    return (COLLECTION_SORTED == m_collectionStatus) ? true : false;
}

bool CertificateCollection::sort()
{
    if (COLLECTION_UNSORTED == m_collectionStatus) {
        sortCollection();
    }
    return (COLLECTION_SORTED == m_collectionStatus) ? true : false;
}

CertificateList CertificateCollection::getChain() const
{
    if (COLLECTION_SORTED != m_collectionStatus) {
        LogError("You must sort certificates first");
        ThrowMsg(Exception::WrongUsage,
                 "You must sort certificates first");
    }
    return m_certList;
}

void CertificateCollection::sortCollection()
{
    // sorting is not necessary
    if (m_certList.empty()) {
        m_collectionStatus = COLLECTION_SORTED;
        return;
    }

    CertificateList sorted;
    std::map<std::string, CertificatePtr> subTransl;
    std::map<std::string, CertificatePtr> issTransl;

    // Sort all certificate by subject
    for (auto it = m_certList.begin(); it != m_certList.end(); ++it) {
        subTransl.insert(std::make_pair(DPL::ToUTF8String((*it)->getOneLine()),(*it)));
    }
    // We need one start certificate
    sorted.push_back(subTransl.begin()->second);
    subTransl.erase(subTransl.begin());

    // Get the issuer from front certificate and find certificate with this subject in subTransl.
    // Add this certificate to the front.
    while (!subTransl.empty()) {
        std::string issuer = DPL::ToUTF8String(sorted.back()->getOneLine(Certificate::FIELD_ISSUER));
        auto it = subTransl.find(issuer);
        if (it == subTransl.end()) {
            break;
        }
        sorted.push_back(it->second);
        subTransl.erase(it);
    }

    // Sort all certificates by issuer
    for (auto it = subTransl.begin(); it != subTransl.end(); ++it) {
        issTransl.insert(std::make_pair(DPL::ToUTF8String((it->second->getOneLine(Certificate::FIELD_ISSUER))),it->second));
    }

    // Get the subject from last certificate and find certificate with such issuer in issTransl.
    // Add this certificate at end.
    while (!issTransl.empty()) {
        std::string sub = DPL::ToUTF8String(sorted.front()->getOneLine());
        auto it = issTransl.find(sub);
        if (it == issTransl.end()) {
            break;
        }
        sorted.push_front(it->second);
        issTransl.erase(it);
    }

    if (!issTransl.empty()) {
        LogWarning("Certificates don't form a valid chain.");
        m_collectionStatus = COLLECTION_CHAIN_BROKEN;
        return;
    }

    m_collectionStatus = COLLECTION_SORTED;
    m_certList = sorted;
}

size_t CertificateCollection::size() const {
    return m_certList.size();
}

bool CertificateCollection::empty() const {
    return m_certList.empty();
}

CertificateCollection::const_iterator CertificateCollection::begin() const {
    return m_certList.begin();
}

CertificateCollection::const_iterator CertificateCollection::end() const {
    return m_certList.end();
}

CertificatePtr CertificateCollection::back() const {
    return m_certList.back();
}

} // namespace ValidationCore

