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
 * @file        file_input.cpp
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of named input pipe
 */
#include <stddef.h>
#include <dpl/file_input.h>
#include <dpl/binary_queue.h>
#include <dpl/log/log.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

namespace VcoreDPL {
namespace // anonymous
{
const size_t DEFAULT_READ_BUFFER_SIZE = 4096;
} // namespace anonymous

FileInput::FileInput() :
    m_fd(-1)
{}

FileInput::FileInput(const std::string& fileName) :
    m_fd(-1)
{
    Open(fileName);
}

FileInput::~FileInput()
{
    Close();
}

void FileInput::Open(const std::string& fileName)
{
    // Open non-blocking
    int fd = TEMP_FAILURE_RETRY(open(fileName.c_str(), O_RDONLY | O_NONBLOCK));

    // Throw an exception if an error occurred
    if (fd == -1) {
        ThrowMsg(Exception::OpenFailed, fileName);
    }

    // Close if any existing
    Close();

    // Save new descriptor
    m_fd = fd;

    LogPedantic("Opened file: " << fileName);
}

void FileInput::Close()
{
    if (m_fd == -1) {
        return;
    }

    if (TEMP_FAILURE_RETRY(close(m_fd)) == -1) {
        Throw(Exception::CloseFailed);
    }

    m_fd = -1;

    LogPedantic("Closed file");
}

BinaryQueueAutoPtr FileInput::Read(size_t size)
{
    size_t bytesToRead = size >
        DEFAULT_READ_BUFFER_SIZE ? DEFAULT_READ_BUFFER_SIZE : size;

    // Malloc default read buffer size
    // It is unmanaged, so it can be then attached directly to binary queue
    void *buffer = malloc(bytesToRead);

    if (buffer == NULL) {
        throw std::bad_alloc();
    }

    LogPedantic("Trying to read " << bytesToRead << " bytes");

    ssize_t result = TEMP_FAILURE_RETRY(read(m_fd, buffer, bytesToRead));

    LogPedantic("Read " << result << " bytes from file");

    if (result > 0) {
        // Succedded to read socket data
        BinaryQueueAutoPtr binaryQueue(new BinaryQueue());

        // Append unmanaged memory
        binaryQueue->AppendUnmanaged(buffer,
                                     result,
                                     &BinaryQueue::BufferDeleterFree,
                                     NULL);

        // Return buffer
        return binaryQueue;
    } else if (result == 0) {
        // Socket was gracefuly closed
        free(buffer);

        // Return empty buffer
        return BinaryQueueAutoPtr(new BinaryQueue());
    } else {
        // Must first save errno value, because it may be altered
        int lastErrno = errno;

        // Free buffer
        free(buffer);

        // Interpret error result
        (void)lastErrno;

        // FIXME: Handle specific errno
        Throw(AbstractInput::Exception::ReadFailed);
    }
}

WaitableHandle FileInput::WaitableReadHandle() const
{
    return static_cast<WaitableHandle>(m_fd);
}
} // namespace VcoreDPL
