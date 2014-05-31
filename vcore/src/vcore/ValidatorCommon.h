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
 * @file        ValidatorCommon.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This file contais definictions of common types used in ValidationCore.
 */
#ifndef _VALIDATORCOMMON_H_
#define _VALIDATORCOMMON_H_

#include <list>
#include <set>
#include <string>

namespace ValidationCore {

/*
 * base deleter func
 */
template <typename T>
struct ValidatorCoreUniversalFree {};

// Template Specialization
#define VC_DECLARE_DELETER(type, function)           \
    template <> \
    struct ValidatorCoreUniversalFree <type> {           \
        void universal_free(type *ptr){                  \
            if (ptr) {                                      \
                function(ptr); }                           \
        }                                                \
    };

template <typename T>
class AutoPtr
{
  public:
    AutoPtr(T *ptr) :
        m_data(ptr)
    {
    }

    AutoPtr(const AutoPtr<T> &second)
    {
        m_data = second.m_data;
        second.m_data = 0;
    }

    AutoPtr & operator=(const AutoPtr &second)
    {
        if (this != &second) {
            ValidatorCoreUniversalFree<T> deleter;
            deleter.universal_free(m_data);
            m_data = second.m_data;
            second.m_data = 0;
        }
        return *this;
    }

    /**
     * overloaded -> operator, so smart ptr could act as ordinary ptr
     */
    T* operator->()
    {
        return m_data;
    }

    ~AutoPtr()
    {
        ValidatorCoreUniversalFree<T> deleter;
        deleter.universal_free(m_data);
    }

    /**
     * get internal pointer
     */
    T* get(void)
    {
        return m_data;
    }

  private:
    mutable T *m_data;
};
} // namespace ValidationCore

#endif // _VALIDATORCOMMON_H_
