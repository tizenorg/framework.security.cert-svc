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
 * @file        process_pipe.cpp
 * @author      Tomasz Iwanek (t.iwanek@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation pipe from process
 */

#include<dpl/test/process_pipe.h>
#include<dpl/log/vcore_log.h>

namespace VcoreDPL {

ProcessPipe::ProcessPipe(PipeErrorPolicy err) : m_file(NULL), m_errPolicy(err)
{
}

ProcessPipe::~ProcessPipe()
{
}

void ProcessPipe::Open(const std::string & command)
{
    if(m_file != NULL)
    {
        ThrowMsg(Exception::DoubleOpen, "Trying to open pipe second time. Close it first");
    }

    std::string stdErrRedirection;
    switch(m_errPolicy)
    {
        case PipeErrorPolicy::NONE:                                      break;
        case PipeErrorPolicy::OFF:   stdErrRedirection = " 2>/dev/null"; break;
        case PipeErrorPolicy::PIPE:  stdErrRedirection = " 2>&1";        break;
        default:                                                         break;
    }

    std::string fcommand = command + stdErrRedirection;
    FILE * file = popen(fcommand.c_str(), "r");

    // Throw an exception if an error occurred
    if (file == NULL) {
        ThrowMsg(FileInput::Exception::OpenFailed, fcommand);
    }

    // Save new descriptor
    m_file = file;
    m_fd = fileno(m_file);

    VcoreLogD("Opened pipe: %s", fcommand.c_str());
}

void ProcessPipe::Close()
{
    if (m_fd == -1) {
        return;
    }

    if (pclose(m_file) == -1) {
        Throw(FileInput::Exception::CloseFailed);
    }

    m_fd = -1;
    m_file = NULL;

    VcoreLogD("Closed pipe");
}

}
