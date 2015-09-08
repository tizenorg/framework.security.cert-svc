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
 * @file        waitable_handle.h
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the header file of waitable handle
 */
#ifndef DPL_WAITABLE_HANDLE_H
#define DPL_WAITABLE_HANDLE_H

#include <dpl/noncopyable.h>
#include <dpl/exception.h>
#include <vector>

namespace VcoreDPL {
/**
 * Waitable unix wait handle definition
 */
typedef int WaitableHandle;

/**
 * Waitable handle list
 */
typedef std::vector<WaitableHandle> WaitableHandleList;

/**
 * Wait mode
 */
class WaitMode
{
  public:
    enum Type
    {
        Read,  ///< Wait for readability state changes
        Write  ///< Wait for writability state changes
    };
};

/**
 * Waitable handle list ex
 */
typedef std::vector<std::pair<WaitableHandle,
                              WaitMode::Type> > WaitableHandleListEx;

/**
 * Waitable handle index list
 */
typedef std::vector<size_t> WaitableHandleIndexList;

/**
 * Wait exceptions
 */
DECLARE_EXCEPTION_TYPE(VcoreDPL::Exception, WaitFailed)

/**
 * Wait for single handle readability
 * Convience function.
 *
 * @return Signaled waitable handle index list
 * @throw WaitFailed Fatal error occurred while waiting for signal
 */
WaitableHandleIndexList WaitForSingleHandle(
    WaitableHandle handle,
    unsigned long miliseconds =
        0xFFFFFFFF);

/**
 * Wait for single handle
 * Convience function.
 *
 * @return Signaled waitable handle index list
 * @throw WaitFailed Fatal error occurred while waiting for signal
 */
WaitableHandleIndexList WaitForSingleHandle(
    WaitableHandle handle,
    WaitMode::Type mode,
    unsigned long miliseconds =
        0xFFFFFFFF);

/**
 * Wait for multiple handles readability
 *
 * @return Signaled waitable handle index list
 * @throw WaitFailed Fatal error occurred while waiting for signal
 */
WaitableHandleIndexList WaitForMultipleHandles(
    const WaitableHandleList &handleList,
    unsigned long miliseconds = 0xFFFFFFFF);

/**
 * Wait for multiple handles readability
 *
 * @return Signaled waitable handle index list
 * @throw WaitFailed Fatal error occurred while waiting for signal
 */
WaitableHandleIndexList WaitForMultipleHandles(
    const WaitableHandleListEx &handleListEx,
    unsigned long miliseconds = 0xFFFFFFFF);
} // namespace VcoreDPL

#endif // DPL_WAITABLE_HANDLE_H
