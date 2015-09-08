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
 * @file        file_input_mapping.h
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the header file of file input mapping
 */
#ifndef DPL_FILE_INPUT_MAPPING_H
#define DPL_FILE_INPUT_MAPPING_H

#include <dpl/exception.h>
#include <dpl/noncopyable.h>

class FileInputMapping
    : private VcoreDPL::Noncopyable
{
public:
    class Exception
    {
    public:
        DECLARE_EXCEPTION_TYPE(VcoreDPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, OpenFailed)
    };

private:
    int m_handle;
    off64_t m_size;
    unsigned char *m_address;

public:
    /**
     * Constructor
     */
    explicit FileInputMapping(const std::string &fileName);

    /**
     * Destructor
     */
    ~FileInputMapping();

    /**
     * Get file mapping total size
     *
     * @return 64-bit size
     */
    off64_t GetSize() const;

    /**
     * Get file mapping base address
     *
     * @return Base address of file mapping
     */
    const unsigned char *GetAddress() const;
};

#endif // DPL_FILE_INPUT_MAPPING_H
