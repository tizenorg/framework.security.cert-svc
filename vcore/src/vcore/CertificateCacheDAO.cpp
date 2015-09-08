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
 * @file       CertificateCacheDAO.cpp
 * @author     Tomasz Swierczek (t.swierczek@samsung.com)
 * @version    0.1
 * @brief      CertificateCacheDAO implementation
 */

#include <vcore/CertificateCacheDAO.h>
#include <vcore/VCorePrivate.h>

#include <dpl/foreach.h>
#include <dpl/log/log.h>
#include <dpl/db/orm.h>
#include <orm_generator_vcore.h>
#include <vcore/Database.h>

using namespace VcoreDPL::DB::ORM;
using namespace VcoreDPL::DB::ORM::vcore;

namespace ValidationCore {

void CertificateCacheDAO::setOCSPStatus(const std::string& cert_chain,
                                        VerificationStatus ocsp_status,
                                        bool end_entity_check,
                                        time_t next_update_time)
{
    Try {
        ScopedTransaction transaction(&ThreadInterface());
        OCSPCachedStatus status;
        status.cert_chain = cert_chain;
        status.end_entity_check = end_entity_check;
        if (getOCSPStatus(&status)) {
            // only need to update data in DB
            Equals<OCSPResponseStorage::cert_chain> e1(
                            VcoreDPL::FromUTF8String(cert_chain));
            Equals<OCSPResponseStorage::end_entity_check> e2(
                            end_entity_check ? 1 : 0);

            OCSPResponseStorage::Row row;

            row.Set_ocsp_status(ocsp_status);
            row.Set_next_update_time(next_update_time);

            VCORE_DB_UPDATE(update, OCSPResponseStorage, &ThreadInterface())
            update->Where(And(e1,e2));
            update->Values(row);
            update->Execute();
        } else {
            // need to insert data
            OCSPResponseStorage::Row row;

            row.Set_cert_chain(VcoreDPL::FromUTF8String(cert_chain));
            row.Set_ocsp_status(ocsp_status);
            row.Set_next_update_time(next_update_time);
            row.Set_end_entity_check(end_entity_check ? 1 : 0);

            VCORE_DB_INSERT(insert, OCSPResponseStorage, &ThreadInterface())
            insert->Values(row);
            insert->Execute();
        }
        transaction.Commit();
    } Catch(VcoreDPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to setOCSPStatus");
    }
}

bool CertificateCacheDAO::getOCSPStatus(OCSPCachedStatus* cached_status)
{
    if (NULL == cached_status) {
        LogError("NULL pointer");
        return false;
    }
    Try {
        Equals<OCSPResponseStorage::cert_chain> e1(
                VcoreDPL::FromUTF8String(cached_status->cert_chain));
        Equals<OCSPResponseStorage::end_entity_check> e2(
                cached_status->end_entity_check ? 1 : 0);

        VCORE_DB_SELECT(select, OCSPResponseStorage, &ThreadInterface())

        select->Where(And(e1,e2));
        std::list<OCSPResponseStorage::Row> rows = select->GetRowList();
        if (1 == rows.size()) {
            OCSPResponseStorage::Row row = rows.front();
            cached_status->ocsp_status = intToVerificationStatus(
                    *(row.Get_ocsp_status()));
            cached_status->next_update_time = *(row.Get_next_update_time());
            return true;
        }

        LogDebug("Cached OCSP status not found");
        return false;
    }
    Catch(VcoreDPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to getOCSPStatus");
    }
}

void CertificateCacheDAO::getOCSPStatusList(
        OCSPCachedStatusList* cached_status_list)
{
    if (NULL == cached_status_list) {
        LogError("NULL pointer");
        return;
    }
    Try {
        VCORE_DB_SELECT(select, OCSPResponseStorage, &ThreadInterface())
        typedef std::list<OCSPResponseStorage::Row> RowList;
        RowList list = select->GetRowList();

        FOREACH(i, list) {
            OCSPCachedStatus status;
            status.cert_chain = VcoreDPL::ToUTF8String(i->Get_cert_chain());
            status.ocsp_status = intToVerificationStatus(
                    *(i->Get_ocsp_status()));
            status.end_entity_check =
                    *(i->Get_end_entity_check()) == 1 ? true : false;
            status.next_update_time = *(i->Get_next_update_time());
            cached_status_list->push_back(status);
        }

    }
    Catch(VcoreDPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to getOCSPStatusList");
    }
}


void CertificateCacheDAO::setCRLResponse(const std::string& distribution_point,
                                         const std::string& crl_body,
                                         time_t next_update_time)
{
    Try {
        ScopedTransaction transaction(&ThreadInterface());
        CRLCachedData data;
        data.distribution_point = distribution_point;
        if (getCRLResponse(&data)) {
            // only need to update data in DB
            VCORE_DB_UPDATE(update, CRLResponseStorage, &ThreadInterface())
            Equals<CRLResponseStorage::distribution_point> e1(
                            VcoreDPL::FromUTF8String(distribution_point));
            CRLResponseStorage::Row row;

            update->Where(e1);
            row.Set_crl_body(VcoreDPL::FromUTF8String(crl_body));
            row.Set_next_update_time(next_update_time);
            update->Values(row);
            update->Execute();
        } else {
            // need to insert data
            VCORE_DB_INSERT(insert, CRLResponseStorage, &ThreadInterface())
            CRLResponseStorage::Row row;

            row.Set_distribution_point(VcoreDPL::FromUTF8String(distribution_point));
            row.Set_crl_body(VcoreDPL::FromUTF8String(crl_body));
            row.Set_next_update_time(next_update_time);
            insert->Values(row);
            insert->Execute();
        }
        transaction.Commit();
    } Catch(VcoreDPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to setOCSPStatus");
    }
}

bool CertificateCacheDAO::getCRLResponse(CRLCachedData* cached_data)
{
    if (NULL == cached_data) {
        LogError("NULL pointer");
        return false;
    }
    Try {
        VCORE_DB_SELECT(select, CRLResponseStorage, &ThreadInterface())
        Equals<CRLResponseStorage::distribution_point> e1(
                VcoreDPL::FromUTF8String(cached_data->distribution_point));

        select->Where(e1);
        std::list<CRLResponseStorage::Row> rows = select->GetRowList();
        if (1 == rows.size()) {
            CRLResponseStorage::Row row = rows.front();
            cached_data->crl_body = VcoreDPL::ToUTF8String(row.Get_crl_body());
            cached_data->next_update_time = *(row.Get_next_update_time());
            return true;
        }

        LogDebug("Cached CRL not found");
        return false;
    }
    Catch(VcoreDPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to getCRLResponse");
    }
}

void CertificateCacheDAO::getCRLResponseList(
        CRLCachedDataList* cached_data_list)
{
    if (NULL == cached_data_list) {
        LogError("NULL pointer");
        return;
    }
    Try {
        VCORE_DB_SELECT(select, CRLResponseStorage, &ThreadInterface())
        typedef std::list<CRLResponseStorage::Row> RowList;
        RowList list = select->GetRowList();

        FOREACH(i, list) {
            CRLCachedData response;
            response.distribution_point = VcoreDPL::ToUTF8String(
                    i->Get_distribution_point());
            response.crl_body = VcoreDPL::ToUTF8String(i->Get_crl_body());
            response.next_update_time = *(i->Get_next_update_time());
            cached_data_list->push_back(response);
        }

    }
    Catch(VcoreDPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to getCRLResponses");
    }
}

void CertificateCacheDAO::clearCertificateCache()
{
    Try {
        ScopedTransaction transaction(&ThreadInterface());
        VCORE_DB_DELETE(del1, OCSPResponseStorage, &ThreadInterface())
        del1->Execute();
        VCORE_DB_DELETE(del2, CRLResponseStorage, &ThreadInterface())
        del2->Execute();
        transaction.Commit();
    }
    Catch(VcoreDPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to clearUserSettings");
    }
}

VerificationStatus CertificateCacheDAO::intToVerificationStatus(int p)
{
    switch (p) {
    case 1:
        return VERIFICATION_STATUS_GOOD;
    case 1 << 1:
        return VERIFICATION_STATUS_REVOKED;
    case 1 << 2:
        return VERIFICATION_STATUS_UNKNOWN;
    case 1 << 3:
        return VERIFICATION_STATUS_VERIFICATION_ERROR;
    case 1 << 4:
        return VERIFICATION_STATUS_NOT_SUPPORT;
    case 1 << 5:
        return VERIFICATION_STATUS_CONNECTION_FAILED;
    case 1 << 6:
        return VERIFICATION_STATUS_ERROR;
    default:
        return VERIFICATION_STATUS_ERROR;
    }
}

} // namespace ValidationCore
