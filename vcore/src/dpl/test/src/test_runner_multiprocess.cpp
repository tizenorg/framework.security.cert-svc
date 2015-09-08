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
 * @file        test_runner_multiprocess.cpp
 * @author      Marcin Niesluchowski (m.niesluchow@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of multiprocess test runner
 */

#include <sys/file.h>
#include <dpl/test/test_runner.h>
#include <dpl/test/test_runner_child.h>
#include <dpl/test/test_runner_multiprocess.h>
#include <poll.h>
#include <limits.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

const int MULTI_TEST_ERROR    = -1;
const int MULTI_TEST_PASS     = 0;
const int MULTI_TEST_FAILED   = 1;
const int MULTI_TEST_IGNORED  = 2;
const int MULTI_TEST_INTERNAL = 3;

}

namespace VcoreDPL {
namespace Test {

SimplePipeWrapper::SimplePipeWrapper()
: PipeWrapper()
{

}

SimplePipeWrapper::~SimplePipeWrapper()
{

}

PipeWrapper::Status SimplePipeWrapper::send(std::string &message)
{
    if (m_pipefd[1] == PIPE_CLOSED) {
           return ERROR;
    }

    if (message.size() > PIPE_BUF-1) {
        return ERROR;
    }

    char buffer[PIPE_BUF] = { 0 };


    for(unsigned int i = 0; i < message.size(); ++i) {
        buffer[i] = message[i];
    }

    return writeHelp(buffer, PIPE_BUF);
}

PipeWrapper::Status SimplePipeWrapper::receive(std::string &data, bool &empty, time_t deadline)
{
    if (m_pipefd[0] == PIPE_CLOSED) {
        return ERROR;
    }

    empty = false;

    data.resize(PIPE_BUF);

    char buffer[PIPE_BUF] = { 0 };

    int ready = 0;
    while (ready != PIPE_BUF) {
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
        int ret = read(m_pipefd[0], &buffer[ready], PIPE_BUF - ready);
        if (ret == -1 && (errno == EAGAIN || errno == EINTR)) {
            continue;
        }

        if (ret == -1) {
            closeHelp(0);
            return ERROR;
        }
        if (ret == 0) {
            empty = true;
            break;
        }

        ready += ret;
    }


    for(unsigned int i = 0; i < PIPE_BUF; ++i){
        if(buffer[i] == 0) {
            data.resize(i);
            return SUCCESS;
        }
        data[i] = buffer[i];
    }

    return ERROR;
}

void RunMultiProc(TestRunner::TestCase procMulti)
{
    SimplePipeWrapper pipe;
    int code = MULTI_TEST_PASS;
    std::string msg = "";
    int pipeReturn;

    int waitStatus;

    pid_t top_pid = getpid();

    if (!pipe.isReady()) {
        throw TestRunner::TestFailed("Pipe creation failed");
    }
    // pipe

    try {
        procMulti();
    } catch (const TestRunner::TestFailed &e) {
        code = MULTI_TEST_FAILED;
        msg = e.GetMessage();
    } catch (const TestRunner::Ignored &e) {
        code = MULTI_TEST_IGNORED;
        msg = e.GetMessage();
    } catch (const VcoreDPL::Exception &e) {
        code = MULTI_TEST_INTERNAL;
        msg = "DPL exception:" + e.GetMessage();
    } catch (const std::exception &) {
        code = MULTI_TEST_INTERNAL;
        msg = "std exception";
    } catch (...) {
        // Unknown exception failure
        code = MULTI_TEST_INTERNAL;
        msg = "unknown exception";
    }

    while (true) {
        pid_t child_pid = wait(&waitStatus);
        if (child_pid == -1) {
            if (errno == ECHILD) {
                if (top_pid == getpid()) {
                    std::string recMsg="";

                    pipe.setUsage(PipeWrapper::READONLY);

                    bool empty=false;
                    while(true) {
                        pipeReturn = pipe.receive(recMsg, empty, time(0) + 10);

                        if (empty) {
                            break;
                        }
                        if (pipeReturn == PipeWrapper::ERROR) {
                            pipe.closeAll();
                            throw TestRunner::TestFailed("Reading pipe error");
                        } else if (pipeReturn == PipeWrapper::TIMEOUT) {
                            pipe.closeAll();
                            throw TestRunner::TestFailed("Timeout error");
                        }
                        msg = msg + "\n" + recMsg;
                    }
                    pipe.closeAll();

                    switch(code) {
                    case MULTI_TEST_PASS:
                        return;
                    case MULTI_TEST_FAILED:
                        throw TestRunner::TestFailed(msg);
                    case MULTI_TEST_IGNORED:
                        throw TestRunner::Ignored(msg);
                    case MULTI_TEST_INTERNAL:
                        throw TestRunner::TestFailed(msg);
                    default:
                        throw TestRunner::TestFailed(msg);
                    }
                } else {
                    pipe.setUsage(PipeWrapper::WRITEONLY);

                    pipeReturn = pipe.send(msg);

                    if (pipeReturn == PipeWrapper::ERROR) {
                        pipe.closeAll();
                        code = MULTI_TEST_ERROR;
                    }

                    exit(code);
                }
            }
        } else if (WIFEXITED(waitStatus)) {
            if ((signed char)WEXITSTATUS(waitStatus) == MULTI_TEST_FAILED) {
                switch (code) {
                    case MULTI_TEST_PASS:
                        code = MULTI_TEST_FAILED;
                        break;
                    case MULTI_TEST_FAILED:
                        break;
                    case MULTI_TEST_IGNORED:
                        code = MULTI_TEST_FAILED;
                        break;
                    case MULTI_TEST_INTERNAL:
                        break;
                    default:
                        break;
                    }
            } else if ((signed char)WEXITSTATUS(waitStatus) == MULTI_TEST_IGNORED) {
                switch (code) {
                case MULTI_TEST_PASS:
                    code = MULTI_TEST_IGNORED;
                    break;
                case MULTI_TEST_FAILED:
                    break;
                case MULTI_TEST_IGNORED:
                    break;
                case MULTI_TEST_INTERNAL:
                    break;
                default:
                    break;
                }
            } else if ((signed char)WEXITSTATUS(waitStatus) == MULTI_TEST_INTERNAL) {
                switch (code) {
                case MULTI_TEST_PASS:
                    code = MULTI_TEST_INTERNAL;
                    break;
                case MULTI_TEST_FAILED:
                    code = MULTI_TEST_INTERNAL;
                    break;
                case MULTI_TEST_IGNORED:
                    code = MULTI_TEST_INTERNAL;
                    break;
                case MULTI_TEST_INTERNAL:
                    break;
                default:
                    break;
                }
            } else  if ((signed char)WEXITSTATUS(waitStatus) != MULTI_TEST_PASS) {
                code = MULTI_TEST_ERROR;
                msg = "PROCESS BAD CODE RETURN";
            }
        }
    }
}
} // namespace Test
} // namespace VcoreDPL
