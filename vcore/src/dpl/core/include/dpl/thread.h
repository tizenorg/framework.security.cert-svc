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
 * @file        thread.h
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of thread
 */
#ifndef DPL_THREAD_H
#define DPL_THREAD_H

#include <dpl/waitable_handle_watch_support.h>
#include <dpl/noncopyable.h>
#include <dpl/exception.h>
#include <dpl/assert.h>
#include <boost/optional.hpp>
#include <stdint.h>
#include <cstdlib>
#include <pthread.h>
#include <thread>
#include <vector>
#include <list>
#include <mutex>

namespace VcoreDPL {
class Thread :
    private Noncopyable,
    public WaitableHandleWatchSupport
{
  public:
    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(VcoreDPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, CreateFailed)
        DECLARE_EXCEPTION_TYPE(Base, DestroyFailed)
        DECLARE_EXCEPTION_TYPE(Base, RunFailed)
        DECLARE_EXCEPTION_TYPE(Base, QuitFailed)
        DECLARE_EXCEPTION_TYPE(Base, UnmanagedThread)
    };

    typedef void (*EventDeleteProc)(void *event, void *userParam);
    typedef void (*EventDispatchProc)(void *event, void *userParam);

  protected:
    /**
     * Main thread entry
     * The method is intended to be overloaded with custom code.
     * Default implementation just executes Exec method to process
     * all thread exents
     */
    virtual int ThreadEntry();

    /**
     * Start processing of thread events
     */
    int Exec();

  private:
    struct InternalEvent
    {
        void *event;
        void *userParam;
        EventDispatchProc eventDispatchProc;
        EventDeleteProc eventDeleteProc;

        InternalEvent(void *eventArg,
                      void *userParamArg,
                      EventDispatchProc eventDispatchProcArg,
                      EventDeleteProc eventDeleteProcArg) :
            event(eventArg),
            userParam(userParamArg),
            eventDispatchProc(eventDispatchProcArg),
            eventDeleteProc(eventDeleteProcArg)
        {}
    };

    struct InternalTimedEvent :
        InternalEvent
    {
        unsigned long dueTimeMiliseconds;
        unsigned long registerTimeMiliseconds;

        InternalTimedEvent(void *eventArg,
                           void *userParamArg,
                           unsigned long dueTimeMilisecondsArg,
                           unsigned long registerTimeMilisecondsArg,
                           EventDispatchProc eventDispatchProcArg,
                           EventDeleteProc eventDeleteProcArg) :
            InternalEvent(eventArg,
                          userParamArg,
                          eventDispatchProcArg,
                          eventDeleteProcArg),
            dueTimeMiliseconds(dueTimeMilisecondsArg),
            registerTimeMiliseconds(registerTimeMilisecondsArg)
        {}

        bool operator<(const InternalTimedEvent &other)
        {
            return registerTimeMiliseconds + dueTimeMiliseconds >
                   other.registerTimeMiliseconds + other.dueTimeMiliseconds;
        }
    };

    // Internal event list
    typedef std::list<InternalEvent> InternalEventList;

    // Internal timed event list
    typedef std::vector<InternalTimedEvent> InternalTimedEventVector;

    // State managment
    std::thread m_thread;
    volatile bool m_abandon;
    volatile bool m_running;
    std::mutex m_stateMutex;
    WaitableEvent m_quitEvent;

    // Event processing
    std::mutex m_eventMutex;
    InternalEventList m_eventList;
    WaitableEvent m_eventInvoker;

    // Timed events processing
    std::mutex m_timedEventMutex;
    InternalTimedEventVector m_timedEventVector;
    WaitableEvent m_timedEventInvoker;

    // WaitableHandleWatchSupport
    virtual Thread *GetInvokerThread();
    virtual void HandleDirectInvoker();
    bool m_directInvoke;

    // Internals
    unsigned long GetCurrentTimeMiliseconds() const;
    void ProcessEvents();
    void ProcessTimedEvents();

    static void *StaticThreadEntry(void *param);

  public:
    explicit Thread();
    virtual ~Thread();

    /**
     * Run thread. Does nothing if thread is already running
     */
    void Run();

    /**
     * Send quit message to thread and wait for its end
     * Does nothing is thread is not running
     */
    void Quit();

    /**
     * Checks if current thread is main one
     * Returns true if it is main program thread, false otherwise
     */
    static bool IsMainThread();

    /**
     * Current thread retrieval
     * Returns DPL thread handle or NULL if it is main program thread
     */
    static Thread *GetCurrentThread();

    /**
     * Low-level event push, usually used only by EventSupport
     */
    void PushEvent(void *event,
                   EventDispatchProc eventDispatchProc,
                   EventDeleteProc eventDeleteProc,
                   void *userParam);

    /**
     * Low-level timed event push, usually used only by EventSupport
     */
    void PushTimedEvent(void *event,
                        double dueTimeSeconds,
                        EventDispatchProc eventDispatchProc,
                        EventDeleteProc eventDeleteProc,
                        void *userParam);

    /**
     * Sleep for a number of seconds
     */
    static void Sleep(uint64_t seconds);

    /**
     * Sleep for a number of miliseconds
     */
    static void MiliSleep(uint64_t miliseconds);

    /**
     * Sleep for a number of microseconds
     */
    static void MicroSleep(uint64_t microseconds);

    /**
     * Sleep for a number of nanoseconds
     */
    static void NanoSleep(uint64_t nanoseconds);
};

extern bool g_TLSforMainCreated;

// In case of using TLV in main thread, pthread_exit(NULL) has to be called in
// this thread explicitly.
// On the other hand, possibly, because of the kernel bug, there exist
// a problem, if any other thread than main exist during pthread_exit call
// (process can become non-responsive)
// TODO further investigation is required.
template<typename Type>
class ThreadLocalVariable :
    public Noncopyable
{
  public:
    typedef Type ValueType;

    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(VcoreDPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, NullReference)
        DECLARE_EXCEPTION_TYPE(Base, KeyCreateFailed)
    };

  private:
    pthread_key_t m_key;

    struct ManagedValue
    {
        ValueType value;
        boost::optional<pthread_key_t> guardKey;
    };

    static void MainThreadExitClean()
    {
        // There is a possible bug in kernel. If this function is called
        // before ALL threads are closed, process will hang!
        // Because of that, by default this function has to be called in well
        // known "threads state".

        // pthread_exit(NULL);
    }

    static void InternalDestroy(void *specific)
    {
        // Destroy underlying type
        ManagedValue *instance = static_cast<ManagedValue *>(specific);
        if (!instance->guardKey) {
            delete instance;
        } else {
            int result = pthread_setspecific(*(instance->guardKey), instance);

            Assert(result == 0 &&
                   "Failed to set thread local variable");
        }
    }

    Type &Reference(bool allowInstantiate = false)
    {
        ManagedValue *instance =
            static_cast<ManagedValue *>(pthread_getspecific(m_key));

        if (!instance) {
            // Check if it is allowed to instantiate
            if (!allowInstantiate) {
                Throw(typename Exception::NullReference);
            }

            // checking, if specific data is created for Main thread
            // If yes, pthread_exit(NULL) is required
            if (!g_TLSforMainCreated) {
                if (Thread::IsMainThread()) {
                    g_TLSforMainCreated = true;
                    atexit(&MainThreadExitClean);
                }
            }

            // Need to instantiate underlying type
            instance = new ManagedValue();

            int result = pthread_setspecific(m_key, instance);

            Assert(result == 0 &&
                   "Failed to set thread local variable");
        }

        return instance->value;
    }

  public:
    ThreadLocalVariable()
    {
        int result = pthread_key_create(&m_key, &InternalDestroy);
        if (result != 0) {
            ThrowMsg(typename Exception::KeyCreateFailed,
                     "Failed to allocate thread local variable: " << result);
        }
    }

    ~ThreadLocalVariable()
    {
        pthread_key_delete(m_key);
    }

    Type &operator=(const Type &other)
    {
        Type &reference = Reference(true);
        reference = other;
        return reference;
    }

    bool IsNull() const
    {
        return pthread_getspecific(m_key) == NULL;
    }

    Type& operator*()
    {
        return Reference();
    }

    const Type& operator*() const
    {
        return Reference();
    }

    const Type* operator->() const
    {
        return &Reference();
    }

    Type* operator->()
    {
        return &Reference();
    }

    bool operator!() const
    {
        return IsNull();
    }

    void Reset()
    {
        ManagedValue *specific =
            static_cast<ManagedValue *>(pthread_getspecific(m_key));

        if (!specific) {
            return;
        }

        // TODO Should be an assert? is it developers fault to Reset Guarded
        // value?
        specific->guardKey = boost::optional<pthread_key_t>();

        InternalDestroy(specific);

        int result = pthread_setspecific(m_key, NULL);

        Assert(result == 0 &&
               "Failed to reset thread local variable");
    }

    // GuardValue(true) allows to defer destroy (by pthread internal
    // functionality) thread specific value until GuardValue(false) will be
    // called.
    void GuardValue(bool guard)
    {
        ManagedValue *instance =
            static_cast<ManagedValue *>(pthread_getspecific(m_key));

        Assert(instance && "Failed to get the value");

        instance->guardKey = guard ? m_key : boost::optional<pthread_key_t>();
    }
};
} // namespace VcoreDPL

#endif // DPL_THREAD_H
