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
#ifndef _SIGNATUREDATA_H_
#define _SIGNATUREDATA_H_

#include <list>
#include <set>
#include <string>

#include <dpl/log/log.h>
#include <dpl/noncopyable.h>
#include <dpl/string.h>

#include <vcore/Certificate.h>
#include <vcore/CertStoreType.h>

namespace ValidationCore {

typedef std::set<std::string> ReferenceSet;
typedef std::list<std::string> ObjectList;

class SignatureData
{
  public:

    SignatureData() :
        m_signatureNumber(-1),
        m_certificateSorted(false)
    {
    }

    SignatureData(std::string fileName, int fileNumber)
      : m_signatureNumber(fileNumber)
      , m_fileName(fileName)
      , m_certificateSorted(false)
    {}

    virtual ~SignatureData()
    {}

    typedef std::list<std::string> IMEIList;
    typedef std::list<std::string> MEIDList;

    const ReferenceSet& getReferenceSet() const
    {
        return m_referenceSet;
    }

    void setReference(const ReferenceSet &referenceSet)
    {
        m_referenceSet = referenceSet;
    }

    CertificateList getCertList(void) const
    {
        return m_certList;
    }

    void setSortedCertificateList(const CertificateList &list)
    {
        m_certList = list;
        m_certificateSorted = true;
    }

    bool isAuthorSignature(void) const
    {
        return m_signatureNumber == -1;
    }

    std::string getSignatureFileName(void) const
    {
        return m_fileName;
    }

    int getSignatureNumber() const
    {
        return m_signatureNumber;
    }

    std::string getRoleURI() const
    {
        return m_roleURI;
    }

    std::string getProfileURI() const
    {
        return m_profileURI;
    }

    bool containObjectReference(const std::string &ref) const
    {
        std::string rName = "#";
        rName += ref;
        return m_referenceSet.end() != m_referenceSet.find(rName);
    }

    ObjectList getObjectList() const
    {
        return m_objectList;
    }

    void setStorageType(const CertStoreId::Set &storeIdSet)
    {
        m_storeIdSet = storeIdSet;
    }

    const CertStoreId::Set& getStorageType(void) const
    {
        return m_storeIdSet;
    }

	const CertStoreId::Type getVisibilityLevel(void) const
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

    const IMEIList& getIMEIList() const
    {
        return m_imeiList;
    }

    const MEIDList& getMEIDList() const
    {
        return m_meidList;
    }

    CertificatePtr getEndEntityCertificatePtr() const
    {
        if (m_certificateSorted) {
            return m_certList.front();
        }
        return CertificatePtr();
    }

    CertificatePtr getRootCaCertificatePtr() const
    {
        if (m_certificateSorted) {
            return m_certList.back();
        }
        return CertificatePtr();
    }

    friend class SignatureReader;

  private:
    ReferenceSet m_referenceSet;
    CertificateList m_certList;

    //TargetRestriction
    IMEIList m_imeiList;
    MEIDList m_meidList;

    /*
     * This number is taken from distributor signature file name.
     * Author signature do not contain any number on the file name.
     * Author signature should have signature number equal to -1.
     */
    int m_signatureNumber;
    std::string m_fileName;
    std::string m_roleURI;
    std::string m_profileURI;
    std::string m_identifier;
    ObjectList m_objectList;
    CertStoreId::Set m_storeIdSet;
    bool m_certificateSorted;
};

typedef std::set<SignatureData> SignatureDataSet;

} // ValidationCore

#endif
