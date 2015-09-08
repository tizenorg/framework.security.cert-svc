/*
 * Copyright (c) 2013 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        test_runner_child.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of test runner
 */
#include <stddef.h>
#include <dpl/test/test_runner.h>
#include <dpl/test/test_runner_child.h>
#include <dpl/test/test_results_collector.h>
#include <dpl/binary_queue.h>
#include <dpl/exception.h>
#include <dpl/scoped_free.h>
#include <dpl/foreach.h>
#include <dpl/colors.h>
#include <pcrecpp.h>
#include <algorithm>
#include <cstdio>
#include <memory.h>
#include <libgen.h>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

namespace {
const int CHILD_TEST_FAIL    = 0;
const int CHILD_TEST_PASS    = 1;
const int CHILD_TEST_IGNORED = 2;

int closeOutput() {
    int devnull;
    int retcode = -1;
    if (-1 == (devnull = TEMP_FAILURE_RETRY(open("/dev/null", O_WRONLY))))
        return -1;

    // replace stdout with /dev/null
    if (-1 == TEMP_FAILURE_RETRY(dup2(devnull, STDOUT_FILENO)))
        goto end;

    // replace stderr with /dev/null
    if (-1 == TEMP_FAILURE_RETRY(dup2(devnull, STDERR_FILENO)))
        goto end;

    retcode = 0;

end:
    close(devnull);
    return retcode;
}

} // namespace anonymous

namespace VcoreDPL {
namespace Test {

PipeWrapper::PipeWrapper()
{
    if (-1 == pipe(m_pipefd)) {
        m_pipefd[0] = PIPE_CLOSED;
        m_pipefd[1] = PIPE_CLOSED;
    }
}

PipeWrapper::~PipeWrapper()
{
    closeHelp(0);
    closeHelp(1);
}

bool PipeWrapper::isReady()
{
    return m_pipefd[0] != PIPE_CLOSED || m_pipefd[1] != PIPE_CLOSED;
}

void PipeWrapper::setUsage(Usage usage)
{
    if (usage == READONLY) {
        closeHelp(1);
    }
    if (usage == WRITEONLY) {
        closeHelp(0);
    }
}

PipeWrapper::Status PipeWrapper::send(int code, std::string &message)
{
    if (m_pipefd[1] == PIPE_CLOSED) {
        return ERROR;
    }

    std::ostringstream output;
    output << toBinaryString(code);
    output << toBinaryString(static_cast<int>(message.size()));
    output << message;

    std::string binary = output.str();
    int size = binary.size();

    if ((writeHelp(&size,
                   sizeof(int)) == ERROR) ||
        (writeHelp(binary.c_str(), size) == ERROR))
    {
        return ERROR;
    }
    return SUCCESS;
}

PipeWrapper::Status PipeWrapper::receive(int &code, std::string &data, time_t deadline)
{
    if (m_pipefd[0] == PIPE_CLOSED) {
        return ERROR;
    }

    int size;
    Status ret;

    if ((ret = readHelp(&size, sizeof(int), deadline)) != SUCCESS) {
        return ret;
    }

    std::vector<char> buffer;
    buffer.resize(size);

    if ((ret = readHelp(&buffer[0], size, deadline)) != SUCCESS) {
        return ret;
    }

    try {
        VcoreDPL::BinaryQueue queue;
        queue.AppendCopy(&buffer[0], size);

        queue.FlattenConsume(&code, sizeof(int));
        queue.FlattenConsume(&size, sizeof(int));

        buffer.resize(size);

        queue.FlattenConsume(&buffer[0], size);
        data.assign(buffer.begin(), buffer.end());
    } catch (VcoreDPL::BinaryQueue::Exception::Base &e) {
        return ERROR;
    }
    return SUCCESS;
}

void PipeWrapper::closeAll()
{
    closeHelp(0);
    closeHelp(1);
}

std::string PipeWrapper::toBinaryString(int data)
{
    char buffer[sizeof(int)];
    memcpy(buffer, &data, sizeof(int));
    return std::string(buffer, buffer + sizeof(int));
}

void PipeWrapper::closeHelp(int desc)
{
    if (m_pipefd[desc] != PIPE_CLOSED) {
        TEMP_FAILURE_RETRY(close(m_pipefd[desc]));
        m_pipefd[desc] = PIPE_CLOSED;
    }
}

PipeWrapper::Status PipeWrapper::writeHelp(const void *buffer, int size)
{
    int ready = 0;
    const char *p = static_cast<const char *>(buffer);
    while (ready != size) {
        int ret = write(m_pipefd[1], &p[ready], size - ready);

        if (ret == -1 && (errno == EAGAIN || errno == EINTR)) {
            continue;
        }

        if (ret == -1) {
            closeHelp(1);
            return ERROR;
        }

        ready += ret;
    }
    return SUCCESS;
}

PipeWrapper::Status PipeWrapper::readHelp(void *buf, int size, time_t deadline)
{
    int ready = 0;
    char *buffer = static_cast<char*>(buf);
    while (ready != size) {
        time_t wait = deadline - time(0);
        wait = wait < 1 ? 1 : wait;
        pollfd fds = { m_pipefd[0], POLLIN, 0 };

        int pollReturn = poll(&fds, 1, wait * 1000);

        if (pollReturn == 0) {
            return TIMEOUT; // Timeout
        }

        if (pollReturn < -1) {
            return ERROR;
        }

        int ret = read(m_pipefd[0], &buffer[ready], size - ready);

        if (ret == -1 && (errno == EAGAIN || errno == EINTR)) {
            continue;
        }

        if (ret == -1 || ret == 0) {
            closeHelp(0);
            return ERROR;
        }

        ready += ret;
    }
    return SUCCESS;
}

void RunChildProc(TestRunner::TestCase procChild)
{
    PipeWrapper pipe;
    if (!pipe.isReady()) {
        throw TestRunner::TestFailed("Pipe creation failed");
    }

    pid_t pid = fork();

    if (pid == -1) {
        throw TestRunner::TestFailed("Child creation failed");
    }

    if (pid != 0) {
        // parent code
        pipe.setUsage(PipeWrapper::READONLY);

        int code;
        std::string message;

        int pipeReturn = pipe.receive(code, message, time(0) + 10);

        if (pipeReturn != PipeWrapper::SUCCESS) { // Timeout or reading error
            pipe.closeAll();
            kill(pid, SIGKILL);
        }

        int status;
        waitpid(pid, &status, 0);

        if (pipeReturn == PipeWrapper::TIMEOUT) {
            throw TestRunner::TestFailed("Timeout");
        }

        if (pipeReturn == PipeWrapper::ERROR) {
            throw TestRunner::TestFailed("Reading pipe error");
        }

        if (code == CHILD_TEST_FAIL) {
            throw TestRunner::TestFailed(message);
        } else if (code == CHILD_TEST_IGNORED) {
            throw TestRunner::Ignored(message);
        }
    } else {
        // child code

        // End Runner after current test
        TestRunnerSingleton::Instance().Terminate();

        int code = CHILD_TEST_PASS;
        std::string msg;

        bool allowLogs = TestRunnerSingleton::Instance().GetAllowChildLogs();

        close(STDIN_FILENO);
        if (!allowLogs) {
            closeOutput(); // if fails nothing we can do
        }

        pipe.setUsage(PipeWrapper::WRITEONLY);

        try {
            procChild();
        } catch (const VcoreDPL::Test::TestRunner::TestFailed &e) {
            msg = e.GetMessage();
            code = CHILD_TEST_FAIL;
        } catch (const VcoreDPL::Test::TestRunner::Ignored &e) {
            msg = e.GetMessage();
            code = CHILD_TEST_IGNORED;
        } catch (...) { // catch all exception generated by "user" code
            msg = "unhandled exeception";
            code = CHILD_TEST_FAIL;
        }

        if (allowLogs) {
            closeOutput();
        }

        pipe.send(code, msg);
    }
}
} // namespace Test
} // namespace VcoreDPL
