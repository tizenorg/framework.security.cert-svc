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
 * @file        CertificateCollection.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     0.1
 * @brief
 */
#ifndef _VALIDATION_CORE_CERTIFICATECOLLECTION_H_
#define _VALIDATION_CORE_CERTIFICATECOLLECTION_H_

#include <list>
#include <string>

#include <dpl/exception.h>

#include <vcore/Certificate.h>

namespace ValidationCore {
/*
 * This class is used to store Certificate Chain.
 * It could serialize chain to std::string in base64 form.
 * It could read chain written in base64 form.
 * It could check if collection creates certificate chain.
 */

class CertificateCollection
{
  public:
    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(DPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, WrongUsage)
    };

    CertificateCollection();

    typedef CertificateList::const_iterator const_iterator;

    /*
     * Remove all certificates from collection.
     */
    void clear();

    /*
     * In current implemenation this function MUST success.
     *
     * This function will add new certificate to collection.
     * This function DOES NOT clean collection.
     */
    void load(const CertificateList &certList);

    /*
     * This function will return false if base64 string is broken
     * (is not encoded in base64 format) or one from certificate
     * is broken (is not encoded in der format).
     *
     * This function will add new certificate to collection.
     * This function DOES NOT clean collection.
     */
    bool load(const std::string &base64);

    /*
     * This function will return all certificates from
     * collection encoded in base64 format.
     */
    std::string toBase64String() const;

    /*
     * This will return all certificate from collection.
     */
    CertificateList getCertificateList() const;

    /*
     * This function will return true if certificates
     * in in this structure were sorted and create
     * certificate chain.

     * Note: You MUST sort certificates first.
     */
    bool isChain() const;

    /*
     * This function will return true if all certificate are
     * able to create certificate chain.
     *
     * This function will sort certificates if collection
     * is not sorted.
     *
     * Note: This function will make all iterators invalid.
     */
    bool sort();

    /*
     * This function will return Certificate chain.
     *
     * First certificate on the list is EndEntity certificate.
     *
     * Last certificate on the list is RootCA certificate or
     * CA certificate if RootCA is not present.
     *
     * Note: You MUST sort certificates first and
     * check if certificates creates proper chain.
     */
    CertificateList getChain() const;

    /*
     * It returns size of certificate collection.
     */
    size_t size() const;

    /*
     * Return true if collection is empty.
     */
    bool empty() const;

    /*
     * This will return end iterator to internal collection.
     *
     * Note: this iterator will lose validity if you call non const
     * method on CertificateCollection class.
     */
    const_iterator begin() const;

    /*
     * This will return end iterator to internal collection.
     *
     * Note: this iterator will lose validity if you call non const
     * method on CertificateCollection class.
     */
    const_iterator end() const;

    /*
     * This function will return the last certificate from collection.
     *
     * Note: There is no point to call this function if certificate
     * collection is not sorted!
     */
    CertificatePtr back() const;

  protected:
    void sortCollection(void);

    enum CollectionStatus
    {
        // Certificate collection are not sorted in any way
        COLLECTION_UNSORTED,
        // Certificate collection creates certificate chain
        COLLECTION_SORTED,
        // Cerfificate collection is not able to create certificate chain
        COLLECTION_CHAIN_BROKEN,
    };

    CollectionStatus m_collectionStatus;
    CertificateList m_certList;
};

typedef std::list<CertificateCollection> CertificateCollectionList;

} // namespace ValidationCore

#endif // _VALIDATION_CORE_CERTIFICATECHAIN_H_
