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
/*!
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     0.2
 * @file        VerficationStatus.cpp
 * @brief       OCSP/CRL status.
 */
#include <vcore/VerificationStatus.h>

namespace ValidationCore {

VerificationStatusSet::VerificationStatusSet()
    : m_verdictMap(0)
{}

void VerificationStatusSet::add(VerificationStatus status) {
    m_verdictMap |= status;
}

bool VerificationStatusSet::contains(VerificationStatus status) const {
    return m_verdictMap & status;
}

bool VerificationStatusSet::isEmpty() const {
    return 0 == m_verdictMap;
}

void VerificationStatusSet::operator+=(const VerificationStatusSet &second) {
    m_verdictMap |= second.m_verdictMap;
}

void VerificationStatusSet::reset() {
    m_verdictMap = 0;
}

VerificationStatus VerificationStatusSet::convertToStatus() const
{
    if (m_verdictMap & VERIFICATION_STATUS_REVOKED) {
        return VERIFICATION_STATUS_REVOKED;
    }

    if (m_verdictMap & VERIFICATION_STATUS_VERIFICATION_ERROR) {
        return VERIFICATION_STATUS_VERIFICATION_ERROR;
    }

    if (m_verdictMap & VERIFICATION_STATUS_ERROR) {
        return VERIFICATION_STATUS_ERROR;
    }

    if (m_verdictMap & VERIFICATION_STATUS_UNKNOWN) {
        return VERIFICATION_STATUS_UNKNOWN;
    }

    if (m_verdictMap & VERIFICATION_STATUS_CONNECTION_FAILED) {
        return VERIFICATION_STATUS_CONNECTION_FAILED;
    }

    if (m_verdictMap & VERIFICATION_STATUS_NOT_SUPPORT) {
        return VERIFICATION_STATUS_NOT_SUPPORT;
    }

    if (m_verdictMap & VERIFICATION_STATUS_GOOD) {
        return VERIFICATION_STATUS_GOOD;
    }

    return VERIFICATION_STATUS_ERROR;
}
} // namespace ValidationCore
