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
 * @file        file_input.h
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of file input
 */
#ifndef DPL_FILE_INPUT_H
#define DPL_FILE_INPUT_H

#include <dpl/noncopyable.h>
#include <dpl/exception.h>
#include <dpl/abstract_waitable_input.h>

namespace VcoreDPL {
class FileInput :
    private Noncopyable,
    public AbstractWaitableInput
{
  public:
    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(VcoreDPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, OpenFailed)
        DECLARE_EXCEPTION_TYPE(Base, CloseFailed)
    };

  protected:
    int m_fd;

  public:
    FileInput();
    FileInput(const std::string &fileName);
    virtual ~FileInput();

    void Open(const std::string &fileName);
    void Close();

    // AbstractInput
    virtual BinaryQueueAutoPtr Read(size_t size);

    // AbstractWaitableInput
    virtual WaitableHandle WaitableReadHandle() const;
};
} // namespace VcoreDPL

#endif // DPL_FILE_INPUT_H
