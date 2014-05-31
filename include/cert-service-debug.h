/*
 * certification service
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd All Rights Reserved 
 *
 * Contact: Kidong Kim <kd0228.kim@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/* To prevent inadvertently including a header twice */
#ifndef CERT_SERVICE_DEBUG_H
#define CERT_SERVICE_DEBUG_H

#ifdef __cplusplus
extern "C" {
#endif	// __cplusplus

/*********************************************************************************/
/* Logging                                                                       */
/*********************************************************************************/
#ifdef CERT_SVC_LOG
#define LOG_TAG "CERT_SVC"
#include <dlog.h>

#elif CERT_SVC_LOG_CONSOLE
#define SLOGV(FMT, ARG ...)	fprintf(stderr, FMT, ##ARG)
#define SLOGD(FMT, ARG ...)	fprintf(stderr, FMT, ##ARG)
#define SLOGI(FMT, ARG ...)	fprintf(stderr, FMT, ##ARG)
#define SLOGE(FMT, ARG ...)	fprintf(stderr, FMT, ##ARG)
#define SLOGW(FMT, ARG ...)	fprintf(stderr, FMT, ##ARG)
#define SLOGF(FMT, ARG ...)	fprintf(stderr, FMT, ##ARG)

#else
#define SLOGV(FMT, ARG ...)	{}
#define SLOGD(FMT, ARG ...)	{}
#define SLOGI(FMT, ARG ...)	{}
#define SLOGE(FMT, ARG ...)	{}
#define SLOGW(FMT, ARG ...)	{}
#define SLOGF(FMT, ARG ...)	{}

#endif

#ifdef __cplusplus
}
#endif	// __cplusplus

#endif	// CERT_SERVICE_DEBUG_H
