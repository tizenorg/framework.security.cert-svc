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
 * @file       CachedCRL.h
 * @author     Tomasz Swierczek (t.swierczek@samsung.com)
 * @version    0.2
 * @brief      Header file for smart cached CRL class
 */

#ifndef _VALIDATION_CORE_CACHED_CRL_H_
#define _VALIDATION_CORE_CACHED_CRL_H_

#include <ctime>
#include <string>

#include <vcore/Certificate.h>
#include <vcore/CertificateCollection.h>
#include <vcore/VerificationStatus.h>
#include <vcore/IAbstractResponseCache.h>

namespace ValidationCore {

class CachedCRL : public IAbstractResponseCache {
public:
    // cache can't be refreshed more frequently than CRL_minTimeValid
    static time_t getCRLMinTimeValid();

    // to be even more secure, cache will be refreshed for certificate at least
    // after CRL_maxTimeValid from last response
    static time_t getCRLMaxTimeValid();

    // upon cache refresh, responses that will be invalid in CRL_refreshBefore
    // seconds will be refreshed
    static time_t getCRLRefreshBefore();

    VerificationStatus check(const CertificateCollection &certs);
    VerificationStatus checkEndEntity(CertificateCollection &certs);
    void updateCache();

    CachedCRL();

    virtual ~CachedCRL();

private:

    // updates CRL cache for distributor URI
    // useExpiredShift ==true should be used in cron/global cache update
    // since it updates all CRLs that will be out of date in next
    // CRL_refreshBefore seconds
    bool updateCRLForUri(const std::string & uri, bool useExpiredShift);
};

} // namespace ValidationCore

#endif /* _VALIDATION_CORE_CACHED_CRL_ */
