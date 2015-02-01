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
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @file        CertStoreType.h
 * @version     1.0
 * @brief       Identification of certificate domain. Certificate domains
 *              were defined in WAC 1.0 documentation. This is a part
 *              should be implemented in wrt-installer.
 */
#ifndef _VALIDATION_CORE_CERTSTORETYPE_H_
#define _VALIDATION_CORE_CERTSTORETYPE_H_

#include <string.h>
#ifdef _MOBILE
#include <boost/optional.hpp>
#endif

namespace ValidationCore {
namespace CertStoreId {
typedef unsigned int Type;

// RootCA certificates for developer mode.
const Type TIZEN_DEVELOPER = 1;
// RootCA certificates for author signatures.
const Type TIZEN_TEST = 1 << 1;
const Type TIZEN_VERIFY = 1 << 2;
// RootCA's visibility level : public
const Type VIS_PUBLIC = 1 << 6;
// RootCA's visibility level : partner
const Type VIS_PARTNER = 1 << 7;
// RootCA's visibility level : partner-operator
const Type VIS_PARTNER_OPERATOR = 1 << 8;
// RootCA's visibility level : partner-manufacturer
const Type VIS_PARTNER_MANUFACTURER = 1 << 9;
// RootCA's visibility level : platform
const Type VIS_PLATFORM = 1 << 10;

class Set
{
  public:
    Set();

    void add(Type second);

	#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
    void add(std::string ocspUrl);
    char* getOcspUrl();
	#endif

	bool contains(Type second) const;
    bool isEmpty() const;

  private:
    Type m_certificateStorage;
	#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
    char* m_ocspUrl;
	#endif
};

} // namespace CertStoreId
} // namespace ValidationCore

#endif //  _VALIDATION_CORE_CERTSTORETYPE_H_
