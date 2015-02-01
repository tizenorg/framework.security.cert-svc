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
 * @file        crl_cache.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Example implementation of memory cache for crl.
 */
#ifndef _CRL_MEMORY_CACHE_H_
#define _CRL_MEMORY_CACHE_H_

#include <map>
#include <string>
#include <vector>

#include <string.h>
#include <time.h>

typedef std::vector<char> BinaryBuffer;

typedef struct CrlRecord_t {
    BinaryBuffer buffer;
    time_t nextUpdate;
} CrlRecord;

typedef std::map<std::string,CrlRecord> MemoryCache;

void memoryCacheWrite(
    const char *distributionPoint,
    const char *body,
    int bodySize,
    time_t nextUpdateTime,
    void *userParam)
{
    MemoryCache *cache = static_cast<MemoryCache*>(userParam);

    CrlRecord record;
    record.buffer.resize(bodySize);
    memcpy(&record.buffer[0], body, bodySize);
    record.nextUpdate = nextUpdateTime;

    cache->insert(std::make_pair(std::string(distributionPoint),record));
}

int memoryCacheRead(
    const char *distributorPoint,
    char **body,
    int *bodySize,
    time_t *nextUpdateTime,
    void *userParam)
{
    MemoryCache *cache = static_cast<MemoryCache*>(userParam);
    auto iter = cache->find(distributorPoint);
    if (iter == cache->end()) {
        return 0;
    }
    CrlRecord record = iter->second;
    *bodySize = record.buffer.size();
    *body = new char[*bodySize];
    memcpy(*body, &record.buffer[0], *bodySize);
    *nextUpdateTime = record.nextUpdate;
    return 1;
}

void memoryCacheFree(
    char *buffer,
    void *)
{
    delete[] buffer;
}

#endif // _CRL_MEMORY_CACHE_H_

