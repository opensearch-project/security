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

import java.util.Arrays;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;

public class HeapBasedRateTracker<ClientIdType> implements RateTracker<ClientIdType> {

    private final Logger log = LogManager.getLogger(this.getClass());

    private final Cache<ClientIdType, ClientRecord> cache;
    private final long timeWindowMs;
    private final int maxTimeOffsets;

    public HeapBasedRateTracker(long timeWindowMs, int allowedTries, int maxEntries) {
        if (allowedTries < 2) {
            throw new IllegalArgumentException("allowedTries must be >= 2");
        }

        this.timeWindowMs = timeWindowMs;
        this.maxTimeOffsets = allowedTries > 2 ? allowedTries - 2 : 0;
        this.cache = CacheBuilder.newBuilder().expireAfterAccess(this.timeWindowMs, TimeUnit.MILLISECONDS).maximumSize(maxEntries).concurrencyLevel(4)
                .removalListener(new RemovalListener<ClientIdType, ClientRecord>() {
                    @Override
                    public void onRemoval(RemovalNotification<ClientIdType, ClientRecord> notification) {
                        if (log.isDebugEnabled()) {
                            log.debug("Removing {}", notification.getKey());
                        }
                    }
                }).build();
    }

    @Override
    public boolean track(ClientIdType clientId) {

        try {
            ClientRecord clientRecord = this.cache.get(clientId, () -> new ClientRecord());

            boolean result = clientRecord.track();

            if (log.isDebugEnabled()) {
                log.debug("track({}): {} => {}", clientId, clientRecord, result);
            }

            return result;

        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void reset(ClientIdType clientId) {
        this.cache.invalidate(clientId);
    }

    private class ClientRecord {
        private long startTime = -1;
        private final int[] timeOffsets = new int[maxTimeOffsets];
        private short timeOffsetStart = -1;
        private short timeOffsetEnd = -1;

        synchronized boolean track() {
            long timestamp = System.currentTimeMillis();

            if (this.startTime == -1 || timestamp - getMostRecent() >= timeWindowMs) {
                this.startTime = timestamp;
                timeOffsetStart = timeOffsetEnd = -1;

                return false;
            }

            if (timestamp - this.startTime >= timeWindowMs) {
                removeExpiredEntries(timestamp);
            } else if (isFull()) {
                shiftFull(timestamp);

                return true;
            }

            if (this.startTime == -1) {
                this.startTime = timestamp;
                timeOffsetStart = timeOffsetEnd = -1;

                return false;
            } else if (this.timeOffsetStart == -1) {
                this.timeOffsets[0] = (int) (timestamp - this.startTime);
                this.timeOffsetStart = 0;
                this.timeOffsetEnd = 0;
            } else {
                short newEnd = next(this.timeOffsetEnd);

                this.timeOffsets[newEnd] = (int) (timestamp - this.startTime);
                this.timeOffsetEnd = newEnd;
            }

            return false;
        }

        private boolean isFull() {
            return this.startTime != 0 && ((timeOffsetStart == timeOffsetEnd + 1)
                    || (timeOffsetStart == 0 && timeOffsetEnd == this.timeOffsets.length - 1) || this.timeOffsets.length == 0);
        }

        private void shiftFull(long timestamp) {
            if (this.timeOffsets.length == 0) {
                this.startTime = timestamp;
                return;
            }
            
            int shiftOffset = this.timeOffsets[this.timeOffsetStart];
            this.startTime += shiftOffset;

            short oldStart = this.timeOffsetStart;
            short second = next(this.timeOffsetStart);

            short i = second;

            for (;;) {
                this.timeOffsets[i] -= shiftOffset;

                if (i == this.timeOffsetEnd) {
                    break;
                }

                i++;

                if (i >= this.timeOffsets.length) {
                    i = 0;
                }
            }

            this.timeOffsetStart = second;
            this.timeOffsets[oldStart] = (int) (timestamp - this.startTime);
            this.timeOffsetEnd = oldStart;
        }

        private long getMostRecent() {
            if (timeOffsetStart == -1) {
                return this.startTime;
            }

            return this.startTime + this.timeOffsets[this.timeOffsetEnd];
        }

        private void removeExpiredEntries(long timestamp) {
            short firstNonExpired = this.findFirstNonExpiredEntry(timestamp);

            if (firstNonExpired == -1) {
                this.startTime = -1;
                this.timeOffsetStart = this.timeOffsetEnd = -1;
                return;
            }

            long newStartTime = this.startTime + this.timeOffsets[firstNonExpired];

            if (firstNonExpired == this.timeOffsetEnd) {
                this.startTime = newStartTime;
                this.timeOffsetStart = this.timeOffsetEnd = -1;
                return;
            }

            short secondNonExpired = next(firstNonExpired);
            int offsetBetweenOldAndNew = this.timeOffsets[firstNonExpired];

            short i = secondNonExpired;

            for (;;) {
                this.timeOffsets[i] -= offsetBetweenOldAndNew;

                if (i == this.timeOffsetEnd) {
                    break;
                }

                i++;

                if (i >= this.timeOffsets.length) {
                    i = 0;
                }
            }

            this.startTime = newStartTime;
            this.timeOffsetStart = secondNonExpired;
        }

        private short next(short i) {
            i++;

            if (i >= this.timeOffsets.length) {
                i = 0;
            }

            return i;
        }

        private short findFirstNonExpiredEntry(long timestamp) {
            short i = this.timeOffsetStart;

            if (i == -1) {
                return -1;
            }

            for (;;) {

                if (timestamp - (this.startTime + this.timeOffsets[i]) < timeWindowMs) {
                    return i;
                }

                if (i == this.timeOffsetEnd) {
                    break;
                }

                i++;

                if (i >= this.timeOffsets.length) {
                    i = 0;
                }

            }

            return -1;
        }

        @Override
        public String toString() {
            return "ClientRecord [startTime=" + startTime + ", timeOffsets=" + Arrays.toString(timeOffsets) + ", timeOffsetStart=" + timeOffsetStart
                    + ", timeOffsetEnd=" + timeOffsetEnd + "]";
        }

    }

}
