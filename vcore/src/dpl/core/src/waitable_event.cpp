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
 * @file        waitable_event.cpp
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of waitable event
 */
#include <stddef.h>
#include <dpl/waitable_event.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <errno.h>

namespace VcoreDPL {
WaitableEvent::WaitableEvent()
{
    if (pipe(m_pipe) == -1) {
        Throw(Exception::CreateFailed);
    }

    if (fcntl(m_pipe[0], F_SETFL, O_NONBLOCK |
              fcntl(m_pipe[0], F_GETFL)) == -1)
    {
        Throw(Exception::CreateFailed);
    }
}

WaitableEvent::~WaitableEvent()
{
    if (TEMP_FAILURE_RETRY(close(m_pipe[0])) == -1) {
        Throw(Exception::DestroyFailed);
    }

    if (TEMP_FAILURE_RETRY(close(m_pipe[1])) == -1) {
        Throw(Exception::DestroyFailed);
    }
}

WaitableHandle WaitableEvent::GetHandle() const
{
    return m_pipe[0];
}

void WaitableEvent::Signal() const
{
    char data = 0;

    if (TEMP_FAILURE_RETRY(write(m_pipe[1], &data, 1)) != 1) {
        Throw(Exception::SignalFailed);
    }
}

void WaitableEvent::Reset() const
{
    char data;

    if (TEMP_FAILURE_RETRY(read(m_pipe[0], &data, 1)) != 1) {
        Throw(Exception::ResetFailed);
    }
}
} // namespace VcoreDPL
