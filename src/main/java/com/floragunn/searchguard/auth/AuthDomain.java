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

package com.floragunn.searchguard.auth;

import java.util.Objects;

import org.elasticsearch.common.settings.Settings;

public class AuthDomain implements Comparable<AuthDomain> {

    private final AuthenticationBackend backend;
    private final AuthorizationBackend abackend;
    private final HTTPAuthenticator httpAuthenticator;
    private final int order;
    private final boolean rolesOnly;

    public AuthDomain(final AuthenticationBackend backend, final AuthorizationBackend abackend, final HTTPAuthenticator httpAuthenticator,
            final int order, final boolean rolesOnly) {
        super();
        this.backend = rolesOnly ? null : Objects.requireNonNull(backend);
        this.abackend = Objects.requireNonNull(abackend);
        this.httpAuthenticator = rolesOnly ? null : Objects.requireNonNull(httpAuthenticator);
        this.order = order;
        this.rolesOnly = rolesOnly;
    }

    public AuthenticationBackend getBackend() {
        return backend;
    }

    public AuthorizationBackend getAbackend() {
        return abackend;
    }

    public HTTPAuthenticator getHttpAuthenticator() {
        return httpAuthenticator;
    }

    public int getOrder() {
        return order;
    }

    public boolean isRolesOnly() {
        return rolesOnly;
    }

    @Override
    public String toString() {
        return "AuthDomain [backend=" + backend + ", abackend=" + abackend + ", httpAuthenticator=" + httpAuthenticator + ", order="
                + order + ", rolesOnly=" + rolesOnly + "]";
    }

    @Override
    public int compareTo(final AuthDomain o) {
        return Integer.compare(this.order, o.order);
    }
}