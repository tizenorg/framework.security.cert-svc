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
#include <vcore/TimeConversion.h>

#include <string.h>

#include <dpl/log/wrt_log.h>
#include <dpl/assert.h>

namespace ValidationCore {

int asn1TimeToTimeT(ASN1_TIME *t, time_t *res)
{
    struct tm tm;
    int offset;

    (*res) = 0;
    if (!ASN1_TIME_check(t)) {
        return -1;
    }

    memset(&tm, 0, sizeof(tm));

#define g2(p) (((p)[0] - '0') * 10 + (p)[1] - '0')
    if (t->type == V_ASN1_UTCTIME) {
        Assert(t->length > 12);

        /*   this code is copied from OpenSSL asn1/a_utctm.c file */
        tm.tm_year = g2(t->data);
        if (tm.tm_year < 50) {
            tm.tm_year += 100;
        }
        tm.tm_mon = g2(t->data + 2) - 1;
        tm.tm_mday = g2(t->data + 4);
        tm.tm_hour = g2(t->data + 6);
        tm.tm_min = g2(t->data + 8);
        tm.tm_sec = g2(t->data + 10);
        if (t->data[12] == 'Z') {
            offset = 0;
        } else {
            Assert(t->length > 16);

            offset = g2(t->data + 13) * 60 + g2(t->data + 15);
            if (t->data[12] == '-') {
                offset = -offset;
            }
        }
        tm.tm_isdst = -1;
    } else {
        Assert(t->length > 14);

        tm.tm_year = g2(t->data) * 100 + g2(t->data + 2);
        tm.tm_mon = g2(t->data + 4) - 1;
        tm.tm_mday = g2(t->data + 6);
        tm.tm_hour = g2(t->data + 8);
        tm.tm_min = g2(t->data + 10);
        tm.tm_sec = g2(t->data + 12);
        if (t->data[14] == 'Z') {
            offset = 0;
        } else {
            Assert(t->length > 18);

            offset = g2(t->data + 15) * 60 + g2(t->data + 17);
            if (t->data[14] == '-') {
                offset = -offset;
            }
        }
        tm.tm_isdst = -1;
    }
#undef g2
    (*res) = timegm(&tm) - offset * 60;
    return 0;
}

int asn1GeneralizedTimeToTimeT(ASN1_GENERALIZEDTIME *tm, time_t *res)
{
    /*
     * This code is based on following assumption:
     * from openssl/a_gentm.c:
     * GENERALIZEDTIME is similar to UTCTIME except the year is
     * represented as YYYY. This stuff treats everything as a two digit
     * field so make first two fields 00 to 99
     */
    const int DATE_BUFFER_LENGTH = 15; // YYYYMMDDHHMMSSZ

    if (NULL == res || NULL == tm) {
        WrtLogE("NULL pointer");
        return -1;
    }

    if (DATE_BUFFER_LENGTH != tm->length || NULL == tm->data) {
        WrtLogE("Invalid ASN1_GENERALIZEDTIME");
        return -1;
    }

    struct tm time_s;
    if (sscanf ((char*)tm->data,
                "%4d%2d%2d%2d%2d%2d",
                &time_s.tm_year,
                &time_s.tm_mon,
                &time_s.tm_mday,
                &time_s.tm_hour,
                &time_s.tm_min,
                &time_s.tm_sec) < 6)
    {
        WrtLogE("Could not extract time data from ASN1_GENERALIZEDTIME");
        return -1;
    }

    time_s.tm_year -= 1900;
    time_s.tm_mon -= 1;
    time_s.tm_isdst = 0;   // UTC
    time_s.tm_gmtoff = 0;  // UTC
    time_s.tm_zone = NULL; // UTC

    *res = mktime(&time_s);

    return 0;
}

} // namespace ValidationCore

