/*
 * Copyright (c) 2013 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        process_pipe.h
 * @author      Tomasz Iwanek (t.iwanek@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation pipe from process
 */
#ifndef PROCESS_PIPE_H
#define PROCESS_PIPE_H

#include <dpl/file_input.h>
#include <dpl/exception.h>

#include <cstdio>

namespace VcoreDPL {

class ProcessPipe : public FileInput
{
public:
    class Exception
    {
    public:
        DECLARE_EXCEPTION_TYPE(VcoreDPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, DoubleOpen)
    };

    enum class PipeErrorPolicy
    {
        NONE,
        OFF,
        PIPE
    };

    explicit ProcessPipe(PipeErrorPolicy err = PipeErrorPolicy::NONE);
    virtual ~ProcessPipe();

    void Open(const std::string &command);
    void Close();

private:
    FILE * m_file;
    PipeErrorPolicy m_errPolicy;
};

}

#endif // PROCESS_PIPE_H
