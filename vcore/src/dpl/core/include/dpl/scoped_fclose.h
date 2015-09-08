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
 * @file        scoped_fclose.h
 * @author      Piotr Marcinkiewicz (p.marcinkiew@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of scoped fclose RAII
 */
#ifndef DPL_SCOPED_FCLOSE_H
#define DPL_SCOPED_FCLOSE_H

#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <string>
#include <dpl/log/vcore_log.h>
#include <dpl/scoped_resource.h>
#include <dpl/errno_string.h>

namespace VcoreDPL {
struct ScopedFClosePolicy
{
    typedef FILE* Type;
    static Type NullValue()
    {
        return NULL;
    }
    static void Destroy(Type file)
    {
        if (file != NULL) {
            // Try to flush first
            if (TEMP_FAILURE_RETRY(fflush(file)) != 0) {
                std::string errString = GetErrnoString();
                VcoreLogD("Failed to fflush scoped fclose error: %s",
                    errString.c_str());
            }

            // fclose cannot be retried, try to close once
            if (fclose(file) != 0) {
                std::string errString = GetErrnoString();
                VcoreLogD("Failed scoped fclose error: %s", errString.c_str());
            }
        }
    }
};

class ScopedFClose : public ScopedResource<ScopedFClosePolicy>
{
    typedef ScopedFClosePolicy Policy;
    typedef ScopedResource<Policy> BaseType;

  public:
    explicit ScopedFClose(FILE* argFileStream = Policy::NullValue()) :
        BaseType(argFileStream)
    {}
};
} // namespace VcoreDPL

#endif // DPL_SCOPED_FCLOSE_H
