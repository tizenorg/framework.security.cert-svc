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
 * @author      Tomasz Morawski(t.morawski@samsung.com)
 * @author      Michal Ciepielski(m.ciepielski@samsung.com)
 * @version     0.2
 * @brief
 */

#ifndef _OCSP_CERT_MGR_UTIL_H_
#define _OCSP_CERT_MGR_UTIL_H_

#include <vcore/Certificate.h>

namespace ValidationCore {
namespace OCSPCertMgrUtil {
void getCertFromStore(X509_NAME *subject,
        X509 **xcert);
CertificatePtr getParentFromStore(const CertificatePtr &certificate);
/*
 * Look for "parent" certificate from store.
 * It returns new certificate chain.
 */
CertificateList completeCertificateChain(const CertificateList &certList);
} // namespace OCSPCertMgrUtil
} // namespace ValidationCore
#endif

