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
/**
 *
 * @file       CachedOCSP.h
 * @author     Tomasz Swierczek (t.swierczek@samsung.com)
 * @version    0.1
 * @brief      Header file for smart cached OCSP class
 */

#ifndef _SRC_VALIDATION_CORE_CACHED_OCSP_
#define _SRC_VALIDATION_CORE_CACHED_OCSP_

#include <vcore/OCSP.h>
#include <vcore/IAbstractResponseCache.h>

namespace ValidationCore {

class CachedOCSP : public IAbstractResponseCache {
  public:
    // cache can't be refreshed more frequently than OCSP_minTimeValid
    static time_t getOCSPMinTimeValid();
    // to be even more secure, cache will be refreshed for certificate at least
    // after OCSP_minTimeValid from last response
    static time_t getOCSPMaxTimeValid();

    // upon cache refresh, responses that will be invalid in OCSP_refreshBefore
    // seconds will be refreshed
    static time_t getOCSPRefreshBefore();

    VerificationStatus check(const CertificateCollection &certs);
    VerificationStatus checkEndEntity(CertificateCollection &certs);
    void updateCache();

    CachedOCSP();

    virtual ~CachedOCSP();

  private:

    void getCertsForEndEntity(const CertificateCollection &certs,
                              CertificateList* clst);
    time_t getNextUpdateTime(time_t now, time_t response_validity);
};

} // namespace ValidationCore

#endif /* _SRC_VALIDATION_CORE_CACHED_OCSP_ */
