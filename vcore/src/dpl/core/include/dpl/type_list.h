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
 * @file        type_list.h
 * @author      Bartosz Janiak (b.janiak@samsung.com)
 * @version     1.0
 * @brief       Generic type list template
 */
#ifndef DPL_TYPE_LIST_H
#define DPL_TYPE_LIST_H

#include <cstddef>

namespace VcoreDPL {
class TypeListGuard
{
  public:
    template<size_t Index>
    struct Element
    {
        struct ERROR_TypeListElementIndexIsOutOfBounds;
        typedef ERROR_TypeListElementIndexIsOutOfBounds Type;
    };

    static const size_t Size = 0;
};

template<typename HeadType, typename TailType>
class TypeList
{
  private:
    class DummyClass
    {};

    template<typename List, size_t Enum>
    struct TypeCounter : public TypeCounter<typename List::Tail, Enum + 1>
    {};

    template<size_t Enum>
    struct TypeCounter<TypeListGuard, Enum>
    {
        static const size_t Size = Enum;
    };

  public:
    typedef TailType Tail;
    typedef HeadType Head;
    typedef TypeList<HeadType, TailType> ThisType;

    template<size_t Index, typename DummyType = DummyClass>
    struct Element
    {
        typedef typename TailType::template Element<Index - 1>::Type Type;
    };

    template<typename DummyType>
    struct Element<0, DummyType>
    {
        typedef HeadType Type;
    };

    template<typename Type, typename DummyType = DummyClass>
    struct Contains
    {
        typedef typename TailType::template Contains<Type>::Yes Yes;
    };

    template<typename DummyType>
    struct Contains<HeadType, DummyType>
    {
        typedef int Yes;
    };

    static const size_t Size = TypeCounter<ThisType, 0>::Size;
};

template<typename T1 = TypeListGuard, typename T2 = TypeListGuard,
         typename T3 = TypeListGuard, typename T4 = TypeListGuard,
         typename T5 = TypeListGuard, typename T6 = TypeListGuard,
         typename T7 = TypeListGuard, typename T8 = TypeListGuard,
         typename T9 = TypeListGuard, typename T10 = TypeListGuard,
         typename T11 = TypeListGuard, typename T12 = TypeListGuard,
         typename T13 = TypeListGuard, typename T14 = TypeListGuard,
         typename T15 = TypeListGuard, typename T16 = TypeListGuard,
         typename T17 = TypeListGuard, typename T18 = TypeListGuard,
         typename T19 = TypeListGuard, typename T20 = TypeListGuard,
         typename T21 = TypeListGuard, typename T22 = TypeListGuard,
         typename T23 = TypeListGuard, typename T24 = TypeListGuard,
         typename T25 = TypeListGuard, typename T26 = TypeListGuard,
         typename T27 = TypeListGuard, typename T28 = TypeListGuard,
         typename T29 = TypeListGuard, typename T30 = TypeListGuard,
         typename T31 = TypeListGuard, typename T32 = TypeListGuard,
         typename T33 = TypeListGuard, typename T34 = TypeListGuard,
         typename T35 = TypeListGuard, typename T36 = TypeListGuard,
         typename T37 = TypeListGuard, typename T38 = TypeListGuard,
         typename T39 = TypeListGuard, typename T40 = TypeListGuard,
         typename T41 = TypeListGuard, typename T42 = TypeListGuard,
         typename T43 = TypeListGuard, typename T44 = TypeListGuard,
         typename T45 = TypeListGuard, typename T46 = TypeListGuard,
         typename T47 = TypeListGuard, typename T48 = TypeListGuard,
         typename T49 = TypeListGuard, typename T50 = TypeListGuard,
         typename T51 = TypeListGuard, typename T52 = TypeListGuard,
         typename T53 = TypeListGuard, typename T54 = TypeListGuard,
         typename T55 = TypeListGuard, typename T56 = TypeListGuard,
         typename T57 = TypeListGuard, typename T58 = TypeListGuard,
         typename T59 = TypeListGuard, typename T60 = TypeListGuard,
         typename T61 = TypeListGuard, typename T62 = TypeListGuard,
         typename T63 = TypeListGuard, typename T64 = TypeListGuard>
struct TypeListDecl
{
    typedef TypeList<T1,
                     typename TypeListDecl<
                         T2, T3, T4, T5, T6, T7, T8,
                         T9, T10, T11, T12, T13, T14, T15,
                         T16, T17, T18, T19, T20, T21, T22,
                         T23, T24, T25, T26, T27, T28, T29,
                         T30, T31, T32, T33, T34, T35, T36,
                         T37, T38, T39, T40, T41, T42, T43,
                         T44, T45, T46, T47, T48, T49, T50,
                         T51, T52, T53, T54, T55, T56, T57,
                         T58, T59, T60, T61, T62, T63, T64>::Type> Type;
};

template<>
struct TypeListDecl<TypeListGuard, TypeListGuard, TypeListGuard, TypeListGuard,
                    TypeListGuard, TypeListGuard, TypeListGuard, TypeListGuard,
                    TypeListGuard, TypeListGuard, TypeListGuard, TypeListGuard,
                    TypeListGuard, TypeListGuard, TypeListGuard, TypeListGuard,
                    TypeListGuard, TypeListGuard, TypeListGuard, TypeListGuard,
                    TypeListGuard, TypeListGuard, TypeListGuard, TypeListGuard,
                    TypeListGuard, TypeListGuard, TypeListGuard, TypeListGuard,
                    TypeListGuard, TypeListGuard, TypeListGuard, TypeListGuard,
                    TypeListGuard, TypeListGuard, TypeListGuard, TypeListGuard,
                    TypeListGuard, TypeListGuard, TypeListGuard, TypeListGuard,
                    TypeListGuard, TypeListGuard, TypeListGuard, TypeListGuard,
                    TypeListGuard, TypeListGuard, TypeListGuard, TypeListGuard,
                    TypeListGuard, TypeListGuard, TypeListGuard, TypeListGuard,
                    TypeListGuard, TypeListGuard, TypeListGuard, TypeListGuard,
                    TypeListGuard, TypeListGuard, TypeListGuard, TypeListGuard,
                    TypeListGuard, TypeListGuard, TypeListGuard, TypeListGuard>
{
    typedef TypeListGuard Type;
};
} // namespace VcoreDPL

#endif // DPL_TYPE_LIST_H
