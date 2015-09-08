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
 * @file        waitable_handle.cpp
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of waitable handle
 */
#include <stddef.h>
#include <dpl/waitable_event.h>
#include <dpl/workaround.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dpl/assert.h>

namespace VcoreDPL {
namespace // anonymous
{
void CheckWaitableHandle(WaitableHandle handle)
{
#ifdef DPL_ENABLE_WAITABLE_HANDLE_BADF_CHECK
    // Try to get descriptor flags
    int result = fcntl(handle, F_GETFL);

    if (result == -1 && errno == EBADF) {
        AssertMsg(0, "CheckWaitableHandle: Invalid WaitableHandle! (EBADF)");
    }

    AssertMsg(result != -1, "CheckWaitableHandle: Invalid WaitableHandle!");
#endif // DPL_ENABLE_WAITABLE_HANDLE_BADF_CHECK
}
} // namespace anonymous

WaitableHandleIndexList WaitForSingleHandle(WaitableHandle handle,
                                            unsigned long miliseconds)
{
    WaitableHandleList waitHandles;
    waitHandles.push_back(handle);
    return WaitForMultipleHandles(waitHandles, miliseconds);
}

WaitableHandleIndexList WaitForSingleHandle(WaitableHandle handle,
                                            WaitMode::Type mode,
                                            unsigned long miliseconds)
{
    WaitableHandleListEx waitHandles;
    waitHandles.push_back(std::make_pair(handle, mode));
    return WaitForMultipleHandles(waitHandles, miliseconds);
}

WaitableHandleIndexList WaitForMultipleHandles(
    const WaitableHandleList &waitableHandleList,
    unsigned long miliseconds)
{
    WaitableHandleListEx handleList;

    for (WaitableHandleList::const_iterator iterator = waitableHandleList.begin();
         iterator != waitableHandleList.end();
         ++iterator)
    {
        // Wait for multiple objects
        handleList.push_back(std::make_pair(*iterator, WaitMode::Read));
    }

    // Do waiting
    return WaitForMultipleHandles(handleList, miliseconds);
}

WaitableHandleIndexList WaitForMultipleHandles(
    const WaitableHandleListEx &waitableHandleListEx,
    unsigned long miliseconds)
{
    fd_set readFds, writeFds, errorFds;

    // Fill sets
    int maxFd = -1;

    FD_ZERO(&readFds);
    FD_ZERO(&writeFds);
    FD_ZERO(&errorFds);

    // Add read wait handles
    for (WaitableHandleListEx::const_iterator iterator =
             waitableHandleListEx.begin();
         iterator != waitableHandleListEx.end();
         ++iterator)
    {
        if (iterator->first > maxFd) {
            maxFd = iterator->first;
        }

        CheckWaitableHandle(iterator->first);

        // Handle errors along with read and write events
        FD_SET(iterator->first, &errorFds);

        if (iterator->second == WaitMode::Read) {
            FD_SET(iterator->first, &readFds);
        } else if (iterator->second == WaitMode::Write) {
            FD_SET(iterator->first, &writeFds);
        }
    }

    // Do select
    timeval timeout;
    timeval *effectiveTimeout = NULL;
    if (miliseconds != 0xFFFFFFFF) {
        timeout.tv_sec = miliseconds / 1000;
        timeout.tv_usec = (miliseconds % 1000) * 1000;
        effectiveTimeout = &timeout;
    }

    if (TEMP_FAILURE_RETRY(select(maxFd + 1, &readFds, &writeFds, &errorFds,
                                  effectiveTimeout)) == -1)
    {
        Throw(WaitFailed);
    }

    // Check results
    WaitableHandleIndexList indexes;
    size_t index = 0;

    for (WaitableHandleListEx::const_iterator iterator =
             waitableHandleListEx.begin();
         iterator != waitableHandleListEx.end();
         ++iterator)
    {
        // Always return errors, no matter what type of listening is set
        if (FD_ISSET(iterator->first, &errorFds)) {
            indexes.push_back(index);
        } else if (iterator->second == WaitMode::Read) {
            if (FD_ISSET(iterator->first, &readFds)) {
                indexes.push_back(index);
            }
        } else if (iterator->second == WaitMode::Write) {
            if (FD_ISSET(iterator->first, &writeFds)) {
                indexes.push_back(index);
            }
        }
        ++index;
    }

    // Successfuly awaited some events or timeout occurred
    return indexes;
}
} // namespace VcoreDPL
