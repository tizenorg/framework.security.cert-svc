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
 * @file        abstract_input.h
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the header file of abstract input
 */
#ifndef DPL_ABSTRACT_INPUT_H
#define DPL_ABSTRACT_INPUT_H

#include <dpl/exception.h>
#include <memory>

namespace VcoreDPL {
class BinaryQueue;
typedef std::auto_ptr<BinaryQueue> BinaryQueueAutoPtr;

class AbstractInput
{
  public:
    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(VcoreDPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, ReadFailed)
    };

  public:
    virtual ~AbstractInput() {}

    /**
     * Read binary data from input
     * If no data is available method returns NULL buffer.
     * In case connection was successfuly close, method returns empty buffer
     *
     * @param[in] size Maximum number of bytes to read from input
     * @return Buffer containing read bytes
     * @throw  ReadFailed
     */
    virtual BinaryQueueAutoPtr Read(size_t size) = 0;
};
} // namespace VcoreDPL

#endif // DPL_ABSTRACT_INPUT_H
