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
#ifndef WRT_ENGINE_SRC_COMMON_SCOPED_GPOINTER_H
#define WRT_ENGINE_SRC_COMMON_SCOPED_GPOINTER_H

#include <cstddef>
#include <glib-object.h>

#include <dpl/scoped_resource.h>
#include <dpl/assert.h>

namespace WRT {
struct ScopedGPointerPolicy
{
    typedef gpointer Type;
    static Type NullValue()
    {
        return NULL;
    }
    static void Destroy(Type pointer)
    {
        if (pointer != NULL) {
            g_object_unref(pointer);
        }
    }
};

template <typename Class>
class ScopedGPointer : public DPL::ScopedResource<ScopedGPointerPolicy>
{
    typedef ScopedGPointerPolicy Policy;
    typedef DPL::ScopedResource<Policy> BaseType;

  public:
    explicit ScopedGPointer(typename Policy::Type pointer =
                Policy::NullValue()) :
        BaseType(pointer)
    {
    }

    Class *operator->() const throw()
    {
        Assert(this->m_value != Policy::NullValue() &&
               "Dereference of scoped NULL pointer!");
        return static_cast<Class *>(this->m_value);
    }

    Class & operator *() const throw()
    {
        Assert(this->m_value != Policy::NullValue() &&
               "Dereference of scoped NULL pointer!");
        return *static_cast<Class *>(this->m_value);
    }
};
} // namespace WRT

#endif // WRT_ENGINE_SRC_COMMON_SCOPED_GPOINTER_H
