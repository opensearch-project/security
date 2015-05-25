/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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

package com.floragunn.searchguard.authentication.backend;

import java.util.concurrent.TimeUnit;

import org.elasticsearch.common.cache.CacheBuilder;
import org.elasticsearch.common.cache.CacheLoader;
import org.elasticsearch.common.cache.LoadingCache;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;

import com.floragunn.searchguard.authentication.AuthCredentials;
import com.floragunn.searchguard.authentication.AuthException;
import com.floragunn.searchguard.authentication.User;

public final class GuavaCachingAuthenticationBackend implements AuthenticationBackend {

    private final ESLogger log = Loggers.getLogger(this.getClass());
    private final Settings settings;
    private final LoadingCache<AuthCredentials, User> cache;
    private final NonCachingAuthenticationBackend backend;

    @Inject
    public GuavaCachingAuthenticationBackend(final NonCachingAuthenticationBackend backend, final Settings settings) {
        this.settings = settings;
        this.backend = backend;

        final CacheLoader<AuthCredentials, User> loader = new CacheLoader<AuthCredentials, User>() {

            @Override
            public User load(final AuthCredentials userPass) throws AuthException {
                return backend.authenticate(userPass);
            }
        };

        cache = CacheBuilder.newBuilder().expireAfterWrite(24, TimeUnit.HOURS).build(loader);
    }

    @Override
    public String toString() {
        return "GuavaCachingAuthenticationBackend [backend=" + backend + "]";
    }

    @Override
    public User authenticate(final AuthCredentials userPass) throws AuthException {
        try {
            return cache.get(userPass);
        } catch (final Exception e) {
            log.error(e.toString(), e);
            throw new AuthException(e.getCause());
        }
    }

}
