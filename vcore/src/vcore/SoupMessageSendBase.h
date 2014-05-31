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
 * @file        SoupMessageSendBase.h
 * @brief       Simple wrapper for soup.
 */
#ifndef _SRC_VALIDATION_CORE_SOUP_MESSAGE_SEND_BASE_H_
#define _SRC_VALIDATION_CORE_SOUP_MESSAGE_SEND_BASE_H_

#include <map>
#include <vector>
#include <string>

#include <libsoup/soup.h>

namespace SoupWrapper {

class SoupMessageSendBase {
  public:

    typedef std::vector<char> MessageBuffer;
    typedef std::map<std::string,std::string> HeaderMap;

    enum RequestStatus {
        REQUEST_STATUS_OK,
        REQUEST_STATUS_CONNECTION_ERROR
    };

    SoupMessageSendBase();

    virtual ~SoupMessageSendBase();

    /**
     * Add specific information to request header.
     *
     * @param[in] property property name (for example "Host")
     * @param[in] value property value (for example "onet.pl:80")
     */
    void setHeader(const std::string &property,
                const std::string &value);

    /**
     * Set request destination.
     *
     * @param[in] host - full path to source (http://onet.pl/index.html)
     */
    void setHost(const std::string &host);

    /**
     * Set body of request.
     *
     * @param[in] contentType (for example: "application/ocsp-request")
     * @param[in] message body of reqeust
     */
    void setRequest(const std::string &contentType,
                const MessageBuffer &message);

    /**
     * Set network timeout. Default is 30 seconds.
     *
     * @param[in] seconds timeout in seconds
     */
    void setTimeout(int seconds);

    /**
     * How many erros soup will accept before he will terminate connection.
     * Default is 5.
     *
     * @param[in] retry number
     */
    void setRetry(int retry);

    /**
     * Get response from serwer.
     */
    MessageBuffer getResponse() const;

  protected:

    SoupMessage* createRequest();

    enum Status {
        STATUS_IDLE,
        STATUS_SEND_SYNC,
        STATUS_SEND_ASYNC
    };

    Status m_status;

    int m_timeout;
    int m_tryCount;

    std::string m_host;
    std::string m_requestType;
    MessageBuffer m_requestBuffer;
    MessageBuffer m_responseBuffer;
    HeaderMap m_headerMap;
};

} // namespace ValidationCore

#endif
