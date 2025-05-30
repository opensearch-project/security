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
import com.google.common.cache.Weigher;
import com.google.common.util.concurrent.UncheckedExecutionException;

import org.opensearch.OpenSearchException;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.common.unit.ByteSizeUnit;
import org.opensearch.core.common.unit.ByteSizeValue;

/**
 * Infrastructure to create user objects. This class has two implementations:
 * <ul>
 *     <li>Caching: Keeps a serialized to unserialized cache and thus speeds up incoming request by making deserialization unnecessary</li>
 *     <li>Simple: This implementation does not keep a cache. This can be used for unit testing, where no cache is necessary.</li>
 * </ul>
 */
public abstract class UserFactory {
    /**
     * Converts a serialized form of a User object to a User obect. This might use a cache.
     *
     * @param serializedBase64 a string with a serialized form of a User object
     * @return A User object. Never returns null.
     * @throws OpenSearchException in case the provided string could not be processed.
     */
    public abstract User fromSerializedBase64(String serializedBase64);

    public static class Simple extends UserFactory {

        @Override
        public User fromSerializedBase64(String serializedBase64) {
            return User.fromSerializedBase64(serializedBase64);
        }
    }

    public static class Caching extends UserFactory {

        /**
         * This setting specifies the maximum estimated byte size of the cache. The size is estimated, so take it
         * with a grain of salt. It shall just serve as a rough limit. The default is 10 MB.
         */
        public static Setting<ByteSizeValue> MAX_SIZE = Setting.memorySizeSetting(
            "plugins.security.transport_user_cache.max_heap_size",
            new ByteSizeValue(10, ByteSizeUnit.MB),
            Setting.Property.NodeScope
        );

        /**
         * This setting specifies the maximum time an entry is kept in the cache. This is solely for saving space;
         * a stale cache is not possible. The default is 1 hour.
         */
        public static Setting<TimeValue> EXPIRE_AFTER_ACCESS = Setting.timeSetting(
            "plugins.security.transport_user_cache.expire_after_access",
            TimeValue.timeValueHours(1),
            Setting.Property.NodeScope
        );

        private final Cache<String, User> serializedBase64ToUserCache;

        public Caching(Settings settings) {
            this.serializedBase64ToUserCache = CacheBuilder.<String, User>newBuilder()
                .weigher((Weigher<String, User>) (key, user) -> 16 + key.length() + user.estimatedByteSize())
                .maximumWeight(MAX_SIZE.get(settings).getBytes())
                .expireAfterAccess(Duration.ofMillis(EXPIRE_AFTER_ACCESS.get(settings).millis()))
                .build();
        }

        public User fromSerializedBase64(String serializedBase64) {
            try {
                return serializedBase64ToUserCache.get(serializedBase64, () -> User.fromSerializedBase64(serializedBase64));
            } catch (ExecutionException | UncheckedExecutionException e) {
                if (e.getCause() instanceof RuntimeException) {
                    throw (RuntimeException) e.getCause();
                } else {
                    throw new RuntimeException(e.getCause());
                }
            }
        }
    }
}
