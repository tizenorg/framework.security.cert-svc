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
 * @file        abstract_output.h
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the header file of abstract output
 */
#ifndef DPL_ABSTRACT_OUTPUT_H
#define DPL_ABSTRACT_OUTPUT_H

#include <dpl/exception.h>
#include <memory>

namespace VcoreDPL {
class BinaryQueue;
typedef std::auto_ptr<BinaryQueue> BinaryQueueAutoPtr;

class AbstractOutput
{
  public:
    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(VcoreDPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, WriteFailed)
    };

  public:
    virtual ~AbstractOutput() {}

    /**
     * Write binary data to output
     * If output is blocked, Write returns zero, if instance is a type of
     * WaitableAbstractOutput one can wait for writability then
     *
     * @param[in] buffer Input buffer with data to be written
     * @param[in] bufferSize Maximum number of bytes to write from buffer
     * @return Number of bytes success successfuly written or zero if output is
     * blocked
     * @throw WriteFailed
     */
    virtual size_t Write(const BinaryQueue &buffer, size_t bufferSize) = 0;
};
} // namespace VcoreDPL

#endif // DPL_ABSTRACT_OUTPUT_H
