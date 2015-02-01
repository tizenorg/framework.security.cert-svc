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
 * @file       CachedOCSP.cpp
 * @author     Tomasz Swierczek (t.swierczek@samsung.com)
 * @version    0.1
 * @brief      Cached OCSP class implementation
 */

#include <string>
#include <time.h>

#include <dpl/foreach.h>
#include <dpl/log/log.h>
#include <dpl/foreach.h>

#include <vcore/OCSP.h>
#include <vcore/OCSPImpl.h>
#include <vcore/CachedOCSP.h>
#include <vcore/Certificate.h>
#include <vcore/CertificateCacheDAO.h>

namespace {

// one hour in seconds
const time_t OCSP_minTimeValid = 3600;      // one hour in seconds

// one week in seconds
const time_t OCSP_maxTimeValid = 3600 * 24 * 7;

// one hour in seconds
const time_t OCSP_refreshBefore = 3600;

} // anonymous namespace

namespace ValidationCore {

time_t CachedOCSP::getOCSPMinTimeValid() {
    return OCSP_minTimeValid;
}

time_t CachedOCSP::getOCSPMaxTimeValid() {
    return OCSP_maxTimeValid;
}

time_t CachedOCSP::getOCSPRefreshBefore() {
    return OCSP_refreshBefore;
}

CachedOCSP::CachedOCSP(){}

CachedOCSP::~CachedOCSP(){}

VerificationStatus CachedOCSP::check(const CertificateCollection &certs)
{
    OCSPCachedStatus db_status;
    time_t now;
    time(&now);

    db_status.cert_chain = certs.toBase64String();
    db_status.end_entity_check = false;

    if (CertificateCacheDAO::getOCSPStatus(&db_status)) {
        LogDebug("Found cache entry for OCSP");
        if (now < db_status.next_update_time) {
            LogDebug("Cache response valid");
            return db_status.ocsp_status;
        }
    }

    // here we need to get OCSP result and add/update cache
    OCSP ocsp;
    CertificateList list = certs.getChain();
    ocsp.setTrustedStore(list);

    VerificationStatusSet statusSet = ocsp.validateCertificateList(list);
    db_status.ocsp_status = statusSet.convertToStatus();
    db_status.next_update_time = ocsp.getResponseValidity();
    CertificateCacheDAO::setOCSPStatus(db_status.cert_chain,
                                       db_status.ocsp_status,
                                       db_status.end_entity_check,
                                       getNextUpdateTime(
                                           now,
                                           db_status.next_update_time));
    return db_status.ocsp_status;
}

VerificationStatus CachedOCSP::checkEndEntity(CertificateCollection &certs)
{
    OCSPCachedStatus db_status;
    time_t now;
    time(&now);

    db_status.cert_chain = certs.toBase64String();
    db_status.end_entity_check = true;

    if (CertificateCacheDAO::getOCSPStatus(&db_status)) {
        LogDebug("Found cache entry for OCSP");
        if (now < db_status.next_update_time) {
            LogDebug("Cache response valid");
            return db_status.ocsp_status;
        }
    }

    // here we need to send request via OCSP and add/update cache
    CertificateList clst;
    getCertsForEndEntity(certs, &clst);

    OCSP ocsp;
    ocsp.setTrustedStore(certs.getCertificateList());

    VerificationStatusSet statusSet = ocsp.validateCertificateList(clst);
    db_status.ocsp_status = statusSet.convertToStatus();
    db_status.next_update_time = ocsp.getResponseValidity();

    CertificateCacheDAO::setOCSPStatus(db_status.cert_chain,
                                       db_status.ocsp_status,
                                       db_status.end_entity_check,
                                       getNextUpdateTime(
                                           now,
                                           db_status.next_update_time));

    return db_status.ocsp_status;
}

void CachedOCSP::updateCache()
{
    time_t now;
    time(&now);
    now += OCSP_refreshBefore;
    OCSPCachedStatusList list;
    CertificateCacheDAO::getOCSPStatusList(&list);
    FOREACH(db_status, list) {
        if (now >= db_status->next_update_time) {
            // this response needs to be refreshed
            CertificateCollection col;
            col.load(db_status->cert_chain);
            if (!col.sort()) {
                LogError("Certificate collection does not create chain.");
                continue;
            }

            OCSP ocsp;
            CertificateList chain = col.getChain();
            ocsp.setTrustedStore(chain);

            VerificationStatusSet statusSet;

            if (db_status->end_entity_check) {
                CertificateList clst;
                getCertsForEndEntity(col, &clst);
                statusSet = ocsp.validateCertificateList(clst);
            } else {
                statusSet = ocsp.validateCertificateList(chain);
            }

            db_status->ocsp_status = statusSet.convertToStatus();
            db_status->next_update_time = ocsp.getResponseValidity();

            CertificateCacheDAO::setOCSPStatus(db_status->cert_chain,
                                               db_status->ocsp_status,
                                               db_status->end_entity_check,
                                               db_status->next_update_time);
        }
    }
}

void CachedOCSP::getCertsForEndEntity(
        const CertificateCollection &certs, CertificateList* clst)
{
    if (NULL == clst) {
        LogError("NULL pointer");
        return;
    }

    if (certs.isChain() && certs.size() >= 2) {
        CertificateList::const_iterator icert = certs.begin();
        clst->push_back(*icert);
        ++icert;
        clst->push_back(*icert);
    }
}

time_t CachedOCSP::getNextUpdateTime(time_t now, time_t response_validity)
{
    long min = now + OCSP_minTimeValid;
    long max = now + OCSP_maxTimeValid;
    if (response_validity < min) {
        return min;
    }
    if (response_validity > max) {
        return max;
    }
    return response_validity;
}

} // namespace ValidationCore
