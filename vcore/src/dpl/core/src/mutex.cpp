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
 * @file        mutex.cpp
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of mutex
 */
#include <stddef.h>
#include <dpl/mutex.h>
#include <dpl/assert.h>
#include <dpl/log/vcore_log.h>
#include <errno.h>

namespace VcoreDPL {
Mutex::Mutex()
{
    if (pthread_mutex_init(&m_mutex, NULL) != 0) {
        int error = errno;

        VcoreLogD("Failed to create mutex. Errno: %i", error);

        ThrowMsg(Exception::CreateFailed,
                 "Failed to create mutex. Errno: " << error);
    }
}

Mutex::~Mutex()
{
    if (pthread_mutex_destroy(&m_mutex) != 0) {
        int error = errno;

        VcoreLogD("Failed to destroy mutex. Errno: %i", error);
    }
}

void Mutex::Lock() const
{
    if (pthread_mutex_lock(&m_mutex) != 0) {
        int error = errno;

        VcoreLogD("Failed to lock mutex. Errno: %i", error);

        ThrowMsg(Exception::LockFailed,
                 "Failed to lock mutex. Errno: " << error);
    }
}

void Mutex::Unlock() const
{
    if (pthread_mutex_unlock(&m_mutex) != 0) {
        int error = errno;

        VcoreLogD("Failed to unlock mutex. Errno: %i", error);

        ThrowMsg(Exception::UnlockFailed,
                 "Failed to unlock mutex. Errno: " << error);
    }
}

Mutex::ScopedLock::ScopedLock(Mutex *mutex) :
    m_mutex(mutex)
{
    Assert(mutex != NULL);
    m_mutex->Lock();
}

Mutex::ScopedLock::~ScopedLock()
{
    Try
    {
        m_mutex->Unlock();
    }
    Catch(Mutex::Exception::UnlockFailed)
    {
        VcoreLogD("Failed to leave mutex scoped lock");
    }
}
} // namespace VcoreDPL
