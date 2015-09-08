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
 * @file        waitable_handle_watch_support.h
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of waitable handle watch
 * support
 */
#ifndef DPL_WAITABLE_HANDLE_WATCH_SUPPORT_H
#define DPL_WAITABLE_HANDLE_WATCH_SUPPORT_H

#include <dpl/waitable_event.h>
#include <dpl/waitable_handle.h>
#include <dpl/exception.h>
#include <list>
#include <map>
#include <mutex>

namespace VcoreDPL {
class Thread;

class WaitableHandleWatchSupport
{
  public:
    class WaitableHandleListener
    {
      public:
        virtual ~WaitableHandleListener() {}

        virtual void OnWaitableHandleEvent(WaitableHandle waitableHandle,
                                           WaitMode::Type mode) = 0;
    };

  protected:
    // Invoker waitable handle
    // Signaled by Add/Remove methods
    // After being signaled one must call Handle invoke to reset invoker
    WaitableHandle WaitableInvokerHandle() const;

    // Waitable handle ex list
    WaitableHandleListEx WaitableWatcherHandles() const;

    // Perform actions for signaled waitable handle
    // Called in execution context, after
    void HandleWatcher(WaitableHandle waitableHandle, WaitMode::Type mode);

    // Perform actions after invoker was signaled
    void InvokerFinished();

    // Get invoker context
    virtual Thread *GetInvokerThread() = 0;

    // Invoke direct invoker
    virtual void HandleDirectInvoker() = 0;

  private:
    // Waitable event watchers
    struct WaitableHandleWatcher
    {
        WaitableHandleListener *listener;
        WaitMode::Type mode;

        WaitableHandleWatcher(WaitableHandleListener *l, WaitMode::Type m) :
            listener(l),
            mode(m)
        {}
    };

    typedef std::list<WaitableHandleWatcher> WaitableHandleListenerList;

    struct WaitableHandleWatchers
    {
        WaitableHandleListenerList listeners;
        size_t readListenersCount;
        size_t writeListenersCount;

        WaitableHandleWatchers() :
            readListenersCount(0),
            writeListenersCount(0)
        {}
    };

    typedef std::map<WaitableHandle,
                     WaitableHandleWatchers> WaitableHandleWatchersMap;

    // Waitable event watch support
    mutable std::recursive_mutex m_watchersMutex;
    WaitableHandleWatchersMap m_watchersMap;
    WaitableEvent m_watchersInvoker;
    WaitableEvent m_watchersInvokerCommit;

    // Invoke call
    void CommitInvoker();

  public:
    /**
     * Constructor
     */
    explicit WaitableHandleWatchSupport();

    /**
     * Destructor
     */
    virtual ~WaitableHandleWatchSupport();

    /**
     * Adds listener for specific waitable event
     *
     * @param[in] listener Listener to attach
     * @param[in] waitableHandle Waitable handle to listen for changes
     * @param[in] mode Type of changes to listen to
     * @return none
     * @see WaitMode::Type
     */
    void AddWaitableHandleWatch(WaitableHandleListener *listener,
                                WaitableHandle waitableHandle,
                                WaitMode::Type mode);

    /**
     * Remove listener for specific waitable event
     *
     * @param[in] listener Listener to detach
     * @param[in] waitableHandle Waitable handle to unlisten for changes
     * @param[in] mode Type of changes to unlisten to
     * @return none
     * @see WaitMode::Type
     */
    void RemoveWaitableHandleWatch(WaitableHandleListener *listener,
                                   WaitableHandle waitableHandle,
                                   WaitMode::Type mode);

};
} // namespace VcoreDPL

#endif // DPL_WAITABLE_HANDLE_WATCH_SUPPORT_H
