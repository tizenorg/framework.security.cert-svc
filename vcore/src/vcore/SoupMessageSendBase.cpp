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
 * @version     0.1
 * @file        SoupMessageSendBase.cpp
 * @brief       Simple wrapper for soup.
 */
#include <vcore/SoupMessageSendBase.h>

#include <dpl/assert.h>
#include <dpl/foreach.h>
#include <dpl/log/log.h>

namespace SoupWrapper {

SoupMessageSendBase::SoupMessageSendBase()
  : m_status(STATUS_IDLE)
  , m_timeout(30)
  , m_tryCount(5)
{}

SoupMessageSendBase::~SoupMessageSendBase(){
    Assert(m_status == STATUS_IDLE);
}

void SoupMessageSendBase::setHeader(const std::string &property, const std::string &value){
    Assert(m_status == STATUS_IDLE);
    m_headerMap[property] = value;
}

void SoupMessageSendBase::setHost(const std::string &host){
    Assert(m_status == STATUS_IDLE);
    m_host = host;
}

void SoupMessageSendBase::setRequest(const std::string &contentType, const MessageBuffer &message){
    Assert(m_status == STATUS_IDLE);
    m_requestType = contentType;
    m_requestBuffer = message;
}

SoupMessageSendBase::MessageBuffer SoupMessageSendBase::getResponse() const {
    Assert(m_status == STATUS_IDLE);
    return m_responseBuffer;
}

void SoupMessageSendBase::setTimeout(int seconds) {
    Assert(m_status == STATUS_IDLE);
    Assert(seconds >= 0);
    m_timeout = seconds;
}

void SoupMessageSendBase::setRetry(int retry) {
    Assert(m_status == STATUS_IDLE);
    Assert(retry >= 0);
    m_tryCount = retry + 1;
}


SoupMessage* SoupMessageSendBase::createRequest(){
    SoupMessage *message;

    LogInfo("Soup message will be send to: " << m_host.c_str());

    if (!m_requestBuffer.empty()) {
        message = soup_message_new("POST", m_host.c_str());
    } else {
        message = soup_message_new("GET", m_host.c_str());
    }

    if (!message) {
        LogError("Error creating request!");
        return 0;
    }

    FOREACH(it, m_headerMap){
        soup_message_headers_append(message->request_headers,
                                    it->first.c_str(),
                                    it->second.c_str());
    }

    if (!m_requestBuffer.empty()) {
        soup_message_set_http_version(message, SOUP_HTTP_1_0);
        soup_message_set_request(message,
          m_requestType.c_str(),
          SOUP_MEMORY_COPY,
          &m_requestBuffer[0],
          m_requestBuffer.size());
    }
//    soup_message_set_flags(message, SOUP_MESSAGE_NO_REDIRECT);
    return message;
}

} // namespace ValidationCore
