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
 * @file       CachedCRL.cpp
 * @author     Tomasz Swierczek (t.swierczek@samsung.com)
 * @version    0.2
 * @brief      Cached CRL class implementation
 */
#include <vcore/CachedCRL.h>

#include <dpl/foreach.h>
#include <dpl/log/wrt_log.h>
#include <dpl/foreach.h>

#include <vcore/CRLImpl.h>
#include <vcore/CertificateCacheDAO.h>
#include <vcore/CRLCacheDAO.h>

namespace {

const time_t CRL_minTimeValid = 3600;          // one hour in seconds

const time_t CRL_maxTimeValid = 3600 * 24 * 7; // one week in seconds

const time_t CRL_refreshBefore = 3600;         // one hour in seconds

time_t getNextUpdateTime(time_t now, time_t response_validity)
{
    time_t min = now + CRL_minTimeValid;
    time_t max = now + CRL_maxTimeValid;
    if (response_validity < min) {
        return min;
    }
    if (response_validity > max) {
        return max;
    }
    return response_validity;
}

} // namespace anonymous

namespace ValidationCore {

time_t CachedCRL::getCRLMinTimeValid() {
    return CRL_minTimeValid;
}

time_t CachedCRL::getCRLMaxTimeValid() {
    return CRL_maxTimeValid;
}

time_t CachedCRL::getCRLRefreshBefore() {
    return CRL_refreshBefore;
}

CachedCRL::CachedCRL(){}
CachedCRL::~CachedCRL(){}

VerificationStatus CachedCRL::check(const CertificateCollection &certs)
{
    CRLImpl crl(new CRLCacheDAO);
    bool allValid = true;
    // we dont check CRL validity since
    // we may use crl for longer time
    // in smart cache than in regular CRL class (time clamping)
    crl.addToStore(certs);
    FOREACH(cert, certs){
        CRL::StringList crlUris = crl.getCrlUris(*cert);
        FOREACH(uri, crlUris) {
            allValid = allValid && updateCRLForUri(*uri,false);
        }
    }
    if (!allValid) {
        // problems with CRL validity
        WrtLogD("Some CRLs not valid");
    }
    CRL::RevocationStatus stat;
    Try {
        stat = crl.checkCertificateChain(certs);
    } Catch(CRLException::InvalidParameter) {
        // List does not form a chain
        return VERIFICATION_STATUS_ERROR;
    }
    if (stat.isRevoked) {
        WrtLogD("Status REVOKED");
        return VERIFICATION_STATUS_REVOKED;
    }
    WrtLogD("Status GOOD");
    return VERIFICATION_STATUS_GOOD;
}

VerificationStatus CachedCRL::checkEndEntity(CertificateCollection &certs)
{
    if (certs.empty()) {
        WrtLogE("Collection empty. This should never happen.");
        WrtLogD("Status ERROR");
        return VERIFICATION_STATUS_ERROR;
    }
    if (!certs.sort()) {
        WrtLogE("Could not find End Entity certificate. "
                "Collection does not form chain.");
        WrtLogD("Status ERROR");
        return VERIFICATION_STATUS_ERROR;
    }
    CRLImpl crl(new CRLCacheDAO);
    bool allValid = true;
    // we dont check CRL validity since
    // we may use crl for longer time
    // in smart cache than in regular CRL class (time clamping)
    crl.addToStore(certs);
    CertificateList::const_iterator icert = certs.begin();
    if (icert != certs.end()) {
        CRL::StringList crlUris = crl.getCrlUris(*icert);
        FOREACH(uri, crlUris) {
            allValid = allValid && updateCRLForUri(*uri,false);
        }
    }
    if (!allValid) {
        // problems with CRL validity
        WrtLogD("Some CRLs not valid");
    }
    CertificateList::const_iterator iter = certs.begin();
    CRL::RevocationStatus stat = crl.checkCertificate(*iter);
    if (stat.isRevoked) {
        WrtLogD("Status REVOKED");
        return VERIFICATION_STATUS_REVOKED;
    }
    WrtLogD("Status GOOD");
    return VERIFICATION_STATUS_GOOD;
}

void CachedCRL::updateCache()
{
    CRLCachedDataList list;
    CertificateCacheDAO::getCRLResponseList(&list);
    FOREACH(db_crl, list) {
        updateCRLForUri(db_crl->distribution_point, true);
    }
}

bool CachedCRL::updateCRLForUri(const std::string &uri, bool useExpiredShift)
{
    using namespace ValidationCore;
    CRLCachedData cachedCRL;
    cachedCRL.distribution_point = uri;
    time_t now;
    time(&now);
    if (useExpiredShift) {
        now += CRL_refreshBefore;
    }
    if (CertificateCacheDAO::getCRLResponse(&cachedCRL)) {
        if (now < cachedCRL.next_update_time) {
            WrtLogD("Cached CRL still valid for: %s", uri.c_str());
            return true;
        }
    }
    // need to download new CRL
    CRLImpl crl(new CRLCacheDAO);
    CRLImpl::CRLDataPtr list = crl.downloadCRL(uri);
    if (!list) {
        WrtLogW("Could not retreive CRL from %s", uri.c_str());
        return false;
    }
    crl.updateCRL(list);
    CertificateCacheDAO::getCRLResponse(&cachedCRL); // save it the way CRL does
    cachedCRL.next_update_time =
            getNextUpdateTime(now,cachedCRL.next_update_time);
    CertificateCacheDAO::setCRLResponse(cachedCRL.distribution_point,
                                        cachedCRL.crl_body,
                                        cachedCRL.next_update_time);
    return true;
}

} // namespace ValidationCore
