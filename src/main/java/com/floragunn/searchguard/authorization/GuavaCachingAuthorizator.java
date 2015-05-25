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

package com.floragunn.searchguard.authorization;

import java.util.concurrent.TimeUnit;

import org.elasticsearch.common.cache.CacheBuilder;
import org.elasticsearch.common.cache.CacheLoader;
import org.elasticsearch.common.cache.LoadingCache;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;

import com.floragunn.searchguard.authentication.AuthCredentials;
import com.floragunn.searchguard.authentication.AuthException;
import com.floragunn.searchguard.authentication.User;

public final class GuavaCachingAuthorizator implements Authorizator {

    private final ESLogger log = Loggers.getLogger(this.getClass());
    private final Settings settings;
    private final LoadingCache<Tuple<User, AuthCredentials>, User> cache;
    private final NonCachingAuthorizator authorizator;

    @Inject
    public GuavaCachingAuthorizator(final NonCachingAuthorizator authorizator, final Settings settings) {
        this.settings = settings;
        this.authorizator = authorizator;

        final CacheLoader<Tuple<User, AuthCredentials>, User> loader = new CacheLoader<Tuple<User, AuthCredentials>, User>() {

            @Override
            public User load(final Tuple<User, AuthCredentials> key) throws AuthException {

                log.trace("Populate roles to cache for {}", key);
                authorizator.fillRoles(key.v1(), key.v2());
                return key.v1();

            }
        };

        cache = CacheBuilder.newBuilder().expireAfterWrite(24, TimeUnit.HOURS).build(loader);
    }

    @Override
    public String toString() {
        return "GuavaCachingAuthorizator [authorizator=" + authorizator + "]";
    }

    @Override
    public void fillRoles(final User user, final AuthCredentials authCreds) throws AuthException {

        log.trace("Return roles from cache for {}", authCreds);

        try {
            final User _user = cache.get(new Tuple<User, AuthCredentials>(user, authCreds));
            user.copyRolesFrom(_user);
        } catch (final Exception e) {
            log.error(e.toString(), e);
            throw new AuthException(e.getCause());
        }
    }

}
