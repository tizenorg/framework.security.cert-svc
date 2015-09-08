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
 * @file        scoped_close.h
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of scoped close RAII
 */
#ifndef DPL_SCOPED_CLOSE_H
#define DPL_SCOPED_CLOSE_H

#include <unistd.h>
#include <cerrno>
#include <string>
#include <dpl/log/vcore_log.h>
#include <dpl/scoped_resource.h>
#include <dpl/errno_string.h>

namespace VcoreDPL {
struct ScopedClosePolicy
{
    typedef int Type;
    static Type NullValue()
    {
        return -1;
    }
    static void Destroy(Type handle)
    {
        if (handle != -1) {
            if (TEMP_FAILURE_RETRY(::fsync(handle)) == -1) {
                std::string errString = GetErrnoString();
                VcoreLogD("Failed to fsync scoped close error: %s",
                    errString.c_str());
            }

            if (::close(handle) == -1) {
                std::string errString = GetErrnoString();
                VcoreLogD("Failed to scoped close error: %s", errString.c_str());
            }
        }
    }
};

class ScopedClose : public ScopedResource<ScopedClosePolicy>
{
    typedef ScopedClosePolicy Policy;
    typedef ScopedResource<Policy> BaseType;
    typedef ScopedClosePolicy::Type Type;

  public:
    explicit ScopedClose(Type handle = Policy::NullValue()) :
        BaseType(handle)
    { }
};
} // namespace VcoreDPL

#endif // DPL_SCOPED_CLOSE_H
