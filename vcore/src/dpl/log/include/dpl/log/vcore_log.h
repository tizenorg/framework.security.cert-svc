/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
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

#ifndef VCORE_LOG_H
#define VCORE_LOG_H

#ifdef DPL_LOGS_ENABLED

#ifndef TIZEN_DEBUG_ENABLE
#define TIZEN_DEBUG_ENABLE
#endif //TIZEN_DEBUG_ENABLE

#else //DPL_LOGS_ENABLED

#undef TIZEN_DEBUG_ENABLE

#endif //DPL_LOGS_ENABLED

// Log tag check
#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "CERT_SVC_VCORE"

#include <dlog.h>

#define COLOR_ERROR   "\033[38;5;160;1m" // bold red
#define COLOR_WARNING "\033[38;5;202;1m" // bold orange
#define COLOR_INFO    "\033[38;5;243;1m" // bold light gray
#define COLOR_DEBUG   "\033[38;5;243;0m" // normal light gray

#define COLOR_END     "\033[0m"

#define INTERNAL_SECURE_LOG __extension__ SECURE_SLOG
#define VCORE_LOG(priority, color, format, ...) \
do { \
    INTERNAL_SECURE_LOG(priority, LOG_TAG, color format "%s", __VA_ARGS__); \
} while(0)

/*
 * Please use following macros
 */

#define VcoreLogD(...) VCORE_LOG(LOG_DEBUG, COLOR_DEBUG, __VA_ARGS__, COLOR_END)
#define VcoreLogI(...) VCORE_LOG(LOG_INFO, COLOR_INFO, __VA_ARGS__, COLOR_END)
#define VcoreLogW(...) VCORE_LOG(LOG_WARN, COLOR_WARNING, __VA_ARGS__, COLOR_END)
#define VcoreLogE(...) VCORE_LOG(LOG_ERROR, COLOR_ERROR, __VA_ARGS__, COLOR_END)

#endif
