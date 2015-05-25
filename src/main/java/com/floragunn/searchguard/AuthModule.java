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

package com.floragunn.searchguard;

import org.elasticsearch.common.inject.AbstractModule;
import org.elasticsearch.common.settings.Settings;

import waffle.windows.auth.IWindowsAuthProvider;
import waffle.windows.auth.impl.WindowsAuthProviderImpl;

import com.floragunn.searchguard.audit.AuditListener;
import com.floragunn.searchguard.audit.ESStoreAuditListener;
import com.floragunn.searchguard.audit.NullStoreAuditListener;
import com.floragunn.searchguard.authentication.backend.AuthenticationBackend;
import com.floragunn.searchguard.authentication.backend.GuavaCachingAuthenticationBackend;
import com.floragunn.searchguard.authentication.backend.NonCachingAuthenticationBackend;
import com.floragunn.searchguard.authentication.backend.simple.SettingsBasedAuthenticationBackend;
import com.floragunn.searchguard.authentication.http.HTTPAuthenticator;
import com.floragunn.searchguard.authentication.http.basic.HTTPBasicAuthenticator;
import com.floragunn.searchguard.authorization.Authorizator;
import com.floragunn.searchguard.authorization.GuavaCachingAuthorizator;
import com.floragunn.searchguard.authorization.NonCachingAuthorizator;
import com.floragunn.searchguard.authorization.simple.SettingsBasedAuthorizator;
import com.floragunn.searchguard.http.DefaultSessionStore;
import com.floragunn.searchguard.http.NullSessionStore;
import com.floragunn.searchguard.http.SessionStore;
import com.floragunn.searchguard.service.SearchGuardConfigService;
import com.floragunn.searchguard.service.SearchGuardService;
import com.floragunn.searchguard.util.ConfigConstants;

public final class AuthModule extends AbstractModule {

    private final Settings settings;

    public AuthModule(final Settings settings) {
        this.settings = settings;
    }

    @Override
    protected void configure() {

        final Class<? extends NonCachingAuthenticationBackend> defaultNonCachingAuthenticationBackend = SettingsBasedAuthenticationBackend.class;
        final Class<? extends HTTPAuthenticator> defaultHTTPAuthenticator = HTTPBasicAuthenticator.class;
        final Class<? extends NonCachingAuthorizator> defaultNonCachingAuthorizator = SettingsBasedAuthorizator.class;

        final Class<? extends NonCachingAuthenticationBackend> authenticationBackend = settings.getAsClass(
                ConfigConstants.SEARCHGUARD_AUTHENTICATION_AUTHENTICATION_BACKEND, defaultNonCachingAuthenticationBackend);

        final Class<? extends HTTPAuthenticator> httpAuthenticator = settings.getAsClass(
                ConfigConstants.SEARCHGUARD_AUTHENTICATION_HTTP_AUTHENTICATOR, defaultHTTPAuthenticator);
        bind(HTTPAuthenticator.class).to(httpAuthenticator).asEagerSingleton();

        final Class<? extends NonCachingAuthorizator> authorizator = settings.getAsClass(
                ConfigConstants.SEARCHGUARD_AUTHENTICATION_AUTHORIZER, defaultNonCachingAuthorizator);

        if (settings.getAsBoolean(ConfigConstants.SEARCHGUARD_AUTHENTICATION_AUTHENTICATION_BACKEND_CACHE_ENABLE, true)) {
            bind(NonCachingAuthenticationBackend.class).to(authenticationBackend).asEagerSingleton();
            bind(AuthenticationBackend.class).to(GuavaCachingAuthenticationBackend.class).asEagerSingleton();
        } else {
            bind(AuthenticationBackend.class).to(authenticationBackend).asEagerSingleton();
        }

        if (settings.getAsBoolean(ConfigConstants.SEARCHGUARD_AUTHENTICATION_AUTHORIZER_CACHE_ENABLE, true)) {
            bind(NonCachingAuthorizator.class).to(authorizator).asEagerSingleton();
            bind(Authorizator.class).to(GuavaCachingAuthorizator.class).asEagerSingleton();
        } else {
            bind(Authorizator.class).to(authorizator).asEagerSingleton();
        }

        if (settings.getAsBoolean(ConfigConstants.SEARCHGUARD_HTTP_ENABLE_SESSIONS, false)) {
            bind(SessionStore.class).to(DefaultSessionStore.class).asEagerSingleton();
        } else {
            bind(SessionStore.class).to(NullSessionStore.class).asEagerSingleton();
        }

        bind(IWindowsAuthProvider.class).to(
                settings.getAsClass(ConfigConstants.SEARCHGUARD_WAFFLE_WINDOWS_AUTH_PROVIDER_IMPL, WindowsAuthProviderImpl.class))
                .asEagerSingleton();

        bind(AuditListener.class).to(
                settings.getAsBoolean(ConfigConstants.SEARCHGUARD_AUDITLOG_ENABLED, true) ? ESStoreAuditListener.class
                        : NullStoreAuditListener.class).asEagerSingleton();

        bind(SearchGuardService.class).asEagerSingleton();

        bind(SearchGuardConfigService.class).asEagerSingleton();
    }

}
