/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */
package org.opensearch.security.user;

import java.time.Duration;
import java.util.concurrent.ExecutionException;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

public abstract class UserFactory {
    public abstract User fromSerializedBase64(String serializedBase64);

    public static class Simple extends UserFactory {

        @Override
        public User fromSerializedBase64(String serializedBase64) {
            return User.fromSerializedBase64(serializedBase64);
        }
    }

    public static class Caching extends UserFactory {
        private final Cache<String, User> serializedBase64ToUserCache;

        public Caching() {
            this.serializedBase64ToUserCache = CacheBuilder.newBuilder().expireAfterAccess(Duration.ofHours(1)).build();
        }

        public User fromSerializedBase64(String serializedBase64) {
            if (this.serializedBase64ToUserCache == null) {
                return User.fromSerializedBase64(serializedBase64);
            } else {
                try {
                    return serializedBase64ToUserCache.get(serializedBase64, () -> User.fromSerializedBase64(serializedBase64));
                } catch (ExecutionException e) {
                    if (e.getCause() instanceof RuntimeException) {
                        throw (RuntimeException) e.getCause();
                    } else {
                        throw new RuntimeException(e);
                    }
                }
            }
        }
    }

}
