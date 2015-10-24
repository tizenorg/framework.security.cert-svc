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
 * @file        SoupMessageSendSync.cpp
 * @brief       Implementation of soup synchronous interface.
 */
#include <vcore/SoupMessageSendSync.h>

#include <memory>
#include <functional>

#include <vconf.h>

#include <dpl/log/wrt_log.h>

namespace SoupWrapper {

SoupMessageSendBase::RequestStatus SoupMessageSendSync::sendSync()
{
    Assert(m_status == STATUS_IDLE);
    m_status = STATUS_SEND_SYNC;

    ScopedGMainContext context(g_main_context_new());

    std::unique_ptr<char,std::function<void(void*)> >
            proxy(vconf_get_str(VCONFKEY_NETWORK_PROXY), free);

    std::unique_ptr <SoupURI, std::function<void(SoupURI*)> >
                   proxyURI(soup_uri_new (proxy.get()), soup_uri_free);

    WrtLogD("Proxy ptr: %s Proxy addr: %s", (void*)proxy.get(), proxy.get());

    for(int tryCount = 0; tryCount < m_tryCount; ++ tryCount){
        WrtLogD("Try(%d) to download %s", tryCount, m_host.c_str());

        ScopedSoupSession session(soup_session_async_new_with_options(
              SOUP_SESSION_ASYNC_CONTEXT,
              &*context,
              SOUP_SESSION_TIMEOUT,
              m_timeout,
              SOUP_SESSION_PROXY_URI,
              proxyURI.get(),
              NULL));

        ScopedSoupMessage msg;

        msg.Reset(createRequest());

        if (!msg) {
            WrtLogE("Unable to send HTTP request.");
            m_status = STATUS_IDLE;
            return REQUEST_STATUS_CONNECTION_ERROR;
        }
        soup_session_send_message(&*session, &*msg);

        // if (SOUP_STATUS_IS_SUCCESSFUL(msg->status_code))

        if (msg->status_code == SOUP_STATUS_OK) {
            m_responseBuffer.resize(msg->response_body->length);
            memcpy(&m_responseBuffer[0],
              msg->response_body->data,
              msg->response_body->length);
            // We are done.
            m_status = STATUS_IDLE;
            return REQUEST_STATUS_OK;
        } else {
            WrtLogW("Soup failed with code [%d] message [%s]", msg->status_code, msg->response_body->data);
        }
    }

    m_status = STATUS_IDLE;
    return REQUEST_STATUS_CONNECTION_ERROR;
}

} // namespave ValidationCore
