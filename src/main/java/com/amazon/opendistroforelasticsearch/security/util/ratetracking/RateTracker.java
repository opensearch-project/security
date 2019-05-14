/*
 * Copyright 2015-2019 floragunn GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.amazon.opendistroforelasticsearch.security.util.ratetracking;

public interface RateTracker<ClientIdType> {

    boolean track(ClientIdType clientId);

    void reset(ClientIdType clientId);

    static <ClientIdType> RateTracker<ClientIdType> create(long timeWindowMs, int allowedTries, int maxEntries) {
        if (allowedTries == 1) {
            return new SingleTryRateTracker<ClientIdType>();
        } else if (allowedTries > 1) {
            return new HeapBasedRateTracker<ClientIdType>(timeWindowMs, allowedTries, maxEntries);
        } else {
            throw new IllegalArgumentException("allowedTries must be > 0: " + allowedTries);
        }
    }

}
