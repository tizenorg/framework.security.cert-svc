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
 * @file        waitable_event.h
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of waitable event
 */
#ifndef DPL_WAITABLE_EVENT_H
#define DPL_WAITABLE_EVENT_H

#include <dpl/waitable_handle.h>
#include <dpl/noncopyable.h>
#include <dpl/exception.h>
#include <vector>

namespace VcoreDPL {
class WaitableEvent :
    private Noncopyable
{
  public:
    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(VcoreDPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, CreateFailed)
        DECLARE_EXCEPTION_TYPE(Base, DestroyFailed)
        DECLARE_EXCEPTION_TYPE(Base, SignalFailed)
        DECLARE_EXCEPTION_TYPE(Base, ResetFailed)
    };

  private:
    int m_pipe[2];

  public:
    WaitableEvent();
    virtual ~WaitableEvent();

    WaitableHandle GetHandle() const;

    void Signal() const;
    void Reset() const;
};
} // namespace VcoreDPL

#endif // DPL_WAITABLE_EVENT_H
