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
 * @file        file_input_mapping.cpp
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of file input mapping
 */
#include <dpl/scoped_close.h>
#include <dpl/log/log.h>
#include <file_input_mapping.h>
#include <iomanip>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

FileInputMapping::FileInputMapping(const std::string &fileName)
    : m_handle(-1),
      m_size(0),
      m_address(NULL)
{
    // Open device and map it to user space
    int file = TEMP_FAILURE_RETRY(open(fileName.c_str(), O_RDONLY));

    if (file == -1)
    {
        int error = errno;
        ThrowMsg(FileInputMapping::Exception::OpenFailed,
                 "Failed to open file. errno = " << error);
    }

    // Scoped close on file
    VcoreDPL::ScopedClose scopedClose(file);

    // Calculate file size
    off64_t size = lseek64(file, 0, SEEK_END);

    if (size == static_cast<off64_t>(-1))
    {
        int error = errno;
        ThrowMsg(FileInputMapping::Exception::OpenFailed,
                 "Failed to seek file. errno = " << error);
    }

    // Map file to usespace
    void *address = mmap(0, static_cast<size_t>(size),
                         PROT_READ, MAP_SHARED, file, 0);

    if (address == MAP_FAILED)
    {
        int error = errno;
        ThrowMsg(FileInputMapping::Exception::OpenFailed,
                 "Failed to map file. errno = " << error);
    }

    // Release scoped close
    m_handle = scopedClose.Release();

    // Save mapped up address
    m_size = size;
    m_address = static_cast<unsigned char *>(address);

    LogPedantic("Created file mapping: " << fileName <<
                " of size: " << m_size <<
                " at address: " << std::hex << static_cast<void *>(m_address));
}

FileInputMapping::~FileInputMapping()
{
    // Close mapping
    if (munmap(m_address, static_cast<size_t>(m_size)) == -1)
    {
        int error = errno;
        LogPedantic("Failed to munmap file. errno = " << error);
    }

    // Close file descriptor
    if (TEMP_FAILURE_RETRY(close(m_handle)) == -1)
    {
        int error = errno;
        LogPedantic("Failed to close file. errno = " << error);
    }
}

off64_t FileInputMapping::GetSize() const
{
    return m_size;
}

const unsigned char *FileInputMapping::GetAddress() const
{
    return m_address;
}
