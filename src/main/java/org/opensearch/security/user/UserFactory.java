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

/**
 * Infrastructure to create user objects. This class has two implementations:
 * <ul>
 *     <li>Caching: Keeps a serialized to unserialized cache and thus speeds up incoming request by making deserialization unnecessary</li>
 *     <li>Simple: This implementation does not keep a cache. This can be used for unit testing, where no cache is necessary.</li>
 * </ul>
 */
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
