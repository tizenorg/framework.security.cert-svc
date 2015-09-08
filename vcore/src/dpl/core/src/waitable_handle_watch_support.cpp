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
 * @file        waitable_handle_watch_support.cpp
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of waitable handle watch
 * support
 */
#include <stddef.h>
#include <dpl/waitable_handle_watch_support.h>
#include <dpl/thread.h>
#include <dpl/log/vcore_log.h>
#include <algorithm>
#include <dpl/assert.h>

namespace VcoreDPL {
WaitableHandleWatchSupport::WaitableHandleWatchSupport()
{}

WaitableHandleWatchSupport::~WaitableHandleWatchSupport()
{
    // Developer assertions
    if (!m_watchersMap.empty()) {
        VcoreLogW("### Leaked watchers map dump ###");

        for (WaitableHandleWatchersMap::const_iterator iterator =
                 m_watchersMap.begin();
             iterator != m_watchersMap.end();
             ++iterator)
        {
            VcoreLogW("###   Waitable handle: %i", iterator->first);

            VcoreLogW("###     Read listeners: %u", iterator->second.readListenersCount);
            VcoreLogW("###     Write listeners: %u", iterator->second.writeListenersCount);

            for (WaitableHandleListenerList::const_iterator listenersIterator =
                     iterator->second.listeners.begin();
                 listenersIterator != iterator->second.listeners.end();
                 ++listenersIterator)
            {
                VcoreLogW("###       Mode: %i. Listener: %p",
                        listenersIterator->mode, listenersIterator->listener);
            }
        }
    }
}

WaitableHandle WaitableHandleWatchSupport::WaitableInvokerHandle() const
{
    return m_watchersInvoker.GetHandle();
}

WaitableHandleListEx WaitableHandleWatchSupport::WaitableWatcherHandles() const
{
    // Critical section
    {
        std::lock_guard<std::recursive_mutex> lock(m_watchersMutex);

        WaitableHandleListEx handleList;

        for (WaitableHandleWatchersMap::const_iterator iterator =
                 m_watchersMap.begin();
             iterator != m_watchersMap.end();
             ++iterator)
        {
            // Register waitable event id for wait
            // Check if there are any read listeners and write listeners
            // and register for both if applicable
            if (iterator->second.readListenersCount > 0) {
                handleList.push_back(std::make_pair(iterator->first,
                                                    WaitMode::Read));
            }

            if (iterator->second.writeListenersCount > 0) {
                handleList.push_back(std::make_pair(iterator->first,
                                                    WaitMode::Write));
            }
        }

        return handleList;
    }
}

void WaitableHandleWatchSupport::InvokerFinished()
{
    VcoreLogD("Invoker finished called");

    // Reset invoker
    m_watchersInvoker.Reset();

    // Commit invoke
    m_watchersInvokerCommit.Signal();
}

void WaitableHandleWatchSupport::HandleWatcher(WaitableHandle waitableHandle,
                                               WaitMode::Type mode)
{
    //
    // Waitable event occurred
    // Now call all listeners for that waitable event. It is possible
    // that some of listeners early disappeared. This is not a problem.
    // Warning: Listeners and/or watcher may also disappear during dispatching
    // handlers!
    //
    VcoreLogD("Waitable event occurred");

    // Critical section for other threads
    {
        std::lock_guard<std::recursive_mutex> lock(m_watchersMutex);

        // Notice: We must carefully call watchers here as they may disappear
        // (zero listeners) or be created during each of handler call
        //         All removed listeners are handled correctly. Adding
        // additional listener to the same waitable handle
        //         during handler dispatch sequence is _not_ supported.
        WaitableHandleWatchersMap trackedWatchers = m_watchersMap;

        for (WaitableHandleWatchersMap::const_iterator trackedWatchersIterator
                 = trackedWatchers.begin();
             trackedWatchersIterator != trackedWatchers.end();
             ++trackedWatchersIterator)
        {
            // Check if this watcher still exists
            // If not, go to next tracked watcher
            if (m_watchersMap.find(trackedWatchersIterator->first) ==
                m_watchersMap.end())
            {
                VcoreLogD("Watcher disappeared during watcher handler");
                continue;
            }

            // Is this is a waitable handle that we are searching for ?
            if (waitableHandle != trackedWatchersIterator->first) {
                continue;
            }

            // Track watcher listeners list
            WaitableHandleListenerList trackedListeners =
                trackedWatchersIterator->second.listeners;

            VcoreLogD("Calling waitable event listeners (%u)...",
                    trackedListeners.size());

            // Notice: We must carefully call listeners here as they may
            // disappear or be created during each of handler call
            //         All removed listeners are handled correctly. Adding
            // additional listener to the same waitable handle
            //         during handler dispatch sequence is should be also
            // handled, as an extremly case.

            // Call all waitable event listeners who listen for that event
            for (WaitableHandleListenerList::const_iterator
                 trackedListenersIterator = trackedListeners.begin();
                 trackedListenersIterator != trackedListeners.end();
                 ++trackedListenersIterator)
            {
                // Check if this watcher still exists
                // If not, there cannot be another one. Must exit now (after
                // break, we actually exit)
                if (m_watchersMap.find(trackedWatchersIterator->first) ==
                    m_watchersMap.end())
                {
                    VcoreLogD("Watcher disappeared during watcher handler");
                    break;
                }

                // Check if this watcher listener still exists
                // If not, go to next tracked watcher listener
                bool listenerStillExists = false;

                for (WaitableHandleListenerList::const_iterator
                     searchListenerIterator =
                         trackedWatchersIterator->second.listeners.begin();
                     searchListenerIterator !=
                     trackedWatchersIterator->second.listeners.end();
                     ++searchListenerIterator)
                {
                    if (searchListenerIterator->listener ==
                        trackedListenersIterator->listener &&
                        searchListenerIterator->mode ==
                        trackedListenersIterator->mode)
                    {
                        listenerStillExists = true;
                        break;
                    }
                }

                if (!listenerStillExists) {
                    VcoreLogD("Watcher listener disappeared during watcher handler");
                    break;
                }

                // Is this is a listener mode that we are searching for ?
                if (mode != trackedListenersIterator->mode) {
                    continue;
                }

                // Call waitable event watch listener
                VcoreLogD("Before tracker listener call...");
                trackedListenersIterator->listener->OnWaitableHandleEvent(
                    trackedWatchersIterator->first,
                    trackedListenersIterator->mode);
                VcoreLogD("After tracker listener call...");
            }

            // Now call all those listeners who registered during listener calls
            // FIXME: Implement! Notice, that scenario may be recursive!

            VcoreLogD("Waitable event listeners called");

            // No more waitable events possible - consistency check
            break;
        }
    }
}

void WaitableHandleWatchSupport::AddWaitableHandleWatch(
    WaitableHandleListener* listener,
    WaitableHandle waitableHandle,
    WaitMode::Type mode)
{
    // Enter waitable event list critical section
    std::lock_guard<std::recursive_mutex> lock(m_watchersMutex);

    // Find proper list to register into
    WaitableHandleWatchersMap::iterator mapIterator = m_watchersMap.find(
            waitableHandle);

    if (mapIterator != m_watchersMap.end()) {
        // Assert if there is no such listener already that is listening in this
        // mode
        for (WaitableHandleListenerList::iterator listenersIterator =
                 mapIterator->second.listeners.begin();
             listenersIterator != mapIterator->second.listeners.end();
             ++listenersIterator)
        {
            // Must not insert same listener-mode pair
            Assert(
                listenersIterator->listener != listener ||
                listenersIterator->mode != mode);
        }
    }

    VcoreLogD("Adding waitable handle watch: %i", waitableHandle);

    // Push new waitable event watch
    if (mapIterator != m_watchersMap.end()) {
        mapIterator->second.listeners.push_back(WaitableHandleWatcher(listener,
                                                                      mode));
    } else {
        m_watchersMap[waitableHandle].listeners.push_back(WaitableHandleWatcher(
                                                              listener, mode));
    }

    // Update counters
    switch (mode) {
    case WaitMode::Read:
        m_watchersMap[waitableHandle].readListenersCount++;
        break;

    case WaitMode::Write:
        m_watchersMap[waitableHandle].writeListenersCount++;
        break;

    default:
        Assert(0);
    }

    // Trigger waitable event invoker to commit changes
    CommitInvoker();

    VcoreLogD("Waitable event watch added and invoker signaled");
}

void WaitableHandleWatchSupport::RemoveWaitableHandleWatch(
    WaitableHandleListener *listener,
    WaitableHandle waitableHandle,
    WaitMode::Type mode)
{
    // Enter waitable event list critical section
    std::lock_guard<std::recursive_mutex> lock(m_watchersMutex);

    // Find proper list with listener
    WaitableHandleWatchersMap::iterator mapIterator = m_watchersMap.find(
            waitableHandle);

    Assert(mapIterator != m_watchersMap.end());

    // Assert if there is such listener and mode
    WaitableHandleListenerList::iterator listIterator =
        mapIterator->second.listeners.end();

    for (WaitableHandleListenerList::iterator listenersIterator =
             mapIterator->second.listeners.begin();
         listenersIterator != mapIterator->second.listeners.end();
         ++listenersIterator)
    {
        // Check same pair listener-mode
        if (listenersIterator->listener == listener &&
            listenersIterator->mode == mode)
        {
            listIterator = listenersIterator;
            break;
        }
    }

    // Same pair listener-mode must exist
    Assert(listIterator != mapIterator->second.listeners.end());

    VcoreLogD("Removing waitable handle watch: %i", waitableHandle);

    // Remove waitable event watch
    mapIterator->second.listeners.erase(listIterator);

    // Update counters
    switch (mode) {
    case WaitMode::Read:
        mapIterator->second.readListenersCount--;
        break;

    case WaitMode::Write:
        mapIterator->second.writeListenersCount--;
        break;

    default:
        Assert(0);
    }

    // If list is empty, remove it too
    if (mapIterator->second.listeners.empty()) {
        m_watchersMap.erase(mapIterator);
    }

    // Trigger waitable event invoker to commit changes
    CommitInvoker();

    VcoreLogD("Waitable event watch removed and invoker signaled");
}

void WaitableHandleWatchSupport::CommitInvoker()
{
    // Check calling context and execute invoker
    if (Thread::GetCurrentThread() == GetInvokerThread()) {
        VcoreLogD("Calling direct invoker");

        // Direct invoker call
        HandleDirectInvoker();
    } else {
        VcoreLogD("Calling indirect invoker");

        // Indirect invoker call
        m_watchersInvoker.Signal();

        WaitableHandleList waitHandles;
        waitHandles.push_back(m_watchersInvokerCommit.GetHandle());
        WaitForMultipleHandles(waitHandles);

        m_watchersInvokerCommit.Reset();
    }
}

} // namespace VcoreDPL
