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
 * @file
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief
 */
#include "WacOrigin.h"

#include <algorithm>
#include <ctype.h>
#include <idna.h>

#include <<dpl/log/log.h>>

#include <iri.h>
#include "ValidatorCommon.h"

namespace {
const std::string SCHEME_HTTP = "http";
const std::string SCHEME_HTTPS = "https";
const int PORT_HTTP = 80;
const int PORT_HTTPS = 443;
}

namespace ValidationCore {
VC_DECLARE_DELETER(iri_struct, iri_destroy)

WacOrigin::WacOrigin(const std::string &url) :
    m_port(0),
    m_parseFailed(false)
{
    parse(url.c_str());
}

WacOrigin::WacOrigin(const char *url) :
    m_port(0),
    m_parseFailed(false)
{
    parse(url);
}

bool WacOrigin::operator==(const WacOrigin &second) const
{
    if (m_parseFailed || second.m_parseFailed) {
        return false;
    }

    return (m_scheme == second.m_scheme) &&
           (m_host == second.m_host) &&
           (m_port == second.m_port);
}

void WacOrigin::parse(const char *url)
{
    // Step are taken from algorihtm:
    // http://www.w3.org/TR/html5/origin-0.html#origin-0

    // Step 1
    // Step 2
    AutoPtr<iri_struct> iri(iri_parse(url));
    if (!iri.get()) {
        m_parseFailed = true;
        return;
    }

    if (iri->scheme) {
        m_scheme = iri->scheme;
    } else {
        m_parseFailed = true;
        return;
    }

    // Step 3 - Skip this point.
    // WAC 2.0 PRV - we are suport only "http" and "https" schemas.

    // Step 4 - Todo

    // Step 5
    std::transform(m_scheme.begin(), m_scheme.end(), m_scheme.begin(), tolower);

    // Step 6 - we only support "http" and "https" schemas
    if ((m_scheme != SCHEME_HTTP) && (m_scheme != SCHEME_HTTPS)) {
        m_parseFailed = true;
        return;
    }

    // Step 7 - Skip. We do not support "file" schema.

    // Step 8
    if (iri->host) {
        m_host = iri->host;
    } else {
        m_parseFailed = true;
        return;
    }

    // Step 9
    char *output = NULL;
    if (IDNA_SUCCESS !=
        idna_to_ascii_lz(m_host.c_str(), &output, IDNA_USE_STD3_ASCII_RULES)) {
        WrtLogE("libidn error");
        m_parseFailed = true;
        free(output);
        return;
    }
    m_host = output;
    free(output);

    // Step 10
    std::transform(m_host.begin(), m_host.end(), m_host.begin(), ::tolower);

    // Step 11
    if (iri->port) {
        m_port = iri->port;
    } else {
        setPort();
    }

    // Step 12 - Skip it. We do not return anything.
    // User should create geters if he need access to schema/host/port.
}

void WacOrigin::setPort()
{
    if (SCHEME_HTTP == m_scheme) {
        m_port = PORT_HTTP;
        return;
    } else if (SCHEME_HTTPS == m_scheme) {
        m_port = PORT_HTTPS;
        return;
    } else {
        WrtLogD("Scheme %s is not support by WAC2.0 ", m_scheme.c_str());
        m_parseFailed = true;
    }
}
} // namespace ValidationCore
