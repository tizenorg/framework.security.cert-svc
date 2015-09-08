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
 *
 * @file       CertificateCacheDAO.h
 * @author     Tomasz Swierczek (t.swierczek@samsung.com)
 * @version    0.1
 * @brief      Header file for class managing CRL and OCSP cached responses
 */

#ifndef _WRT_SRC_CONFIGURATION_CERTIFICATE_CACHE_DAO_H_
#define _WRT_SRC_CONFIGURATION_CERTIFICATE_CACHE_DAO_H_

#include <string>
#include <list>

#include <dpl/exception.h>

#include <vcore/VerificationStatus.h>
#include <vcore/CRLCacheInterface.h>

namespace ValidationCore {

struct OCSPCachedStatus
{
    std::string cert_chain;
    VerificationStatus ocsp_status;
    bool end_entity_check;
    time_t next_update_time;
};

typedef std::list<OCSPCachedStatus> OCSPCachedStatusList;

typedef std::list<CRLCachedData> CRLCachedDataList;

class CertificateCacheDAO {
  public:
    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(VcoreDPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, DatabaseError)
    };

    // OCSP statuses

    static void setOCSPStatus(const std::string& cert_chain,
                              VerificationStatus ocsp_status,
                              bool end_entity_check,
                              time_t next_update_time);

    /*
     * fill cert_chain and end_entity_check in cached_status
     * returns true iff cached status found without errors
     */
    static bool getOCSPStatus(OCSPCachedStatus* cached_status);
    static void getOCSPStatusList(OCSPCachedStatusList* cached_status_list);

    // CRL responses

    static void setCRLResponse(const std::string& distribution_point,
                               const std::string& crl_body,
                               time_t next_update_time);
    static void setCRLResponse(CRLCachedData *ptr) {
        setCRLResponse(
            ptr->distribution_point,
            ptr->crl_body,
            ptr->next_update_time);
    }
    /*
     * fill distribution_point
     * returns true iff cached list for dist. point found without errors
     */
    static bool getCRLResponse(CRLCachedData* cached_data);
    static void getCRLResponseList(CRLCachedDataList* cached_data_list);


    // clears CRL and OCSP cached data
    static void clearCertificateCache();

  private:

    static VerificationStatus intToVerificationStatus(int p);

    CertificateCacheDAO()
    {
    }
};

} // namespace ValidationCore

#endif /* _WRT_SRC_CONFIGURATION_CERTIFICATE_CACHE_DAO_H_ */
