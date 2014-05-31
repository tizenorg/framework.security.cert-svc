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
 * @file        SoupMessageSendAsync.h
 * @brief       Routines for certificate validation over OCSP
 */
#ifndef _SRC_VALIDATION_CORE_SOUP_MESSAGE_SEND_ASYNC_H_
#define _SRC_VALIDATION_CORE_SOUP_MESSAGE_SEND_ASYNC_H_

#include <map>
#include <vector>

#include <dpl/assert.h>

#include <dpl/event/inter_context_delegate.h>

#include <vcore/SoupMessageSendBase.h>

namespace SoupWrapper {

class SoupMessageSendAsync
  : public SoupMessageSendBase
  , public DPL::Event::ICDelegateSupport<SoupMessageSendAsync>
{
    typedef DPL::Event::ICDelegate<SoupSession*, SoupMessage*, void*> SoupDelegate;
  public:
    void sendAsync() {
        Assert(m_status == STATUS_IDLE);
        Assert(!m_soupSession);
        Assert(!m_soupMessage);

        m_status = STATUS_SEND_ASYNC;
        m_tryLeft = m_tryCount;
        m_mainContext = g_main_context_new();

        if (!m_mainContext){
            m_status = STATUS_IDLE;

            // call the delegate to outside with error!
            return;
        }

        m_soupSession = soup_session_async_new_with_options(
            SOUP_SESSION_ASYNC_CONTEXT,
            m_mainContext,
            SOUP_SESSION_TIMEOUT,
            m_timeout,
            NULL);

        if (!m_soupSession){
            m_status = STATUS_IDLE;
            g_object_unref(m_mainContext);
            m_mainContext = 0;

            // call the deletage to outside with error!
            return;
        }

        m_soupMessage = createRequest();

        if (!m_soupMessage){
            m_status = STATUS_IDLE;
            g_object_unref(m_soupSession);
            m_soupSession = 0;
            g_object_unref(m_mainContext);
            m_mainContext = 0;

            // call the delegate to outsize with error!
            return;
        }

        sendAsyncIterationStart();
    }

  protected:

    struct SoupDelegateOpaque {
        SoupDelegate dlg;
    };

    void sendAsyncIterationStart(){
        // ICDelegate could be called only once.
        // We can set user data only once.
        // We need nasty hack because we will call ICDelegate m_tryCount times.
        SoupDelegateOpaque *opaq = new SoupDelegateOpaque;
        opaq->dlg = makeICDelegate(&SoupMessageSendAsync::requestReceiver);

        soup_session_queue_message(m_soupSession,
                                   m_soupMessage,
                                   soupSessionCallback,
                                   reinterpret_cast<gpointer>(opaq));
    }

    void sendAsyncIteration(SoupDelegateOpaque *opaq){
        // Replace used ICDelegate with new one without changing
        // userdata ;-)
        opaq->dlg = makeICDelegate(&SoupMessageSendAsync::requestReceiver);
        soup_session_requeue_message(m_soupSession,
                                     m_soupMessage);
    }

    void requestReceiver(SoupSession *session, SoupMessage *msg, void *opaque){
        // We are in thread which called sendAsync function.
        Assert(session == m_soupSession);
        Assert(msg == m_soupMessage);
        Assert(opaque != 0);
        Assert(m_status == STATUS_SEND_ASYNC);

        m_tryLeft--;

        if (msg->status_code == SOUP_STATUS_OK) {
            m_responseBuffer.resize(msg->response_body->length);
            memcpy(&m_responseBuffer[0],
              msg->response_body->data,
              msg->response_body->length);
            // We are done.
            m_status = STATUS_IDLE;
            delete static_cast<SoupDelegateOpaque*>(opaque);

            // call the delegate to outside!
            return;
        }

        // Error protocol //
        if (m_tryLeft <= 0) {
            m_status = STATUS_IDLE;
            delete static_cast<SoupDelegateOpaque*>(opaque);

            // call the delegate to outside with error!
            return;
        }

        // create delegate and send the request once again.
        sendAsyncIteration(reinterpret_cast<SoupDelegateOpaque*>(opaque));
    }

    static void soupSessionCallback(SoupSession *session,
                                    SoupMessage *msg,
                                    gpointer userdata)
    {
        // We are in main thread. We need to switch context.
        // This delegate can switch context to dpl thread or main thread.
        SoupDelegateOpaque *opaque;
        opaque = reinterpret_cast<SoupDelegateOpaque*>(userdata);
        opaque->dlg(session, msg, userdata);
    }

    int m_tryLeft;

    GMainContext *m_mainContext;
    SoupSession *m_soupSession;
    SoupMessage *m_soupMessage;
};

} // namespace ValidationCore

#endif
