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

public class AuthDomain implements Comparable<AuthDomain> {

    private final AuthenticationBackend backend;
    private final HTTPAuthenticator httpAuthenticator;
    private final int order;
    private final boolean requirePreFlight;

    public AuthDomain(final AuthenticationBackend backend, final HTTPAuthenticator httpAuthenticator, boolean requirePreFlight, final int order) {
        super();
        this.backend = Objects.requireNonNull(backend);
        this.httpAuthenticator = Objects.requireNonNull(httpAuthenticator);
        this.order = order;
        this.requirePreFlight = requirePreFlight;
    }

    public boolean isRequirePreFlight() {
        return requirePreFlight;
    }

    public AuthenticationBackend getBackend() {
        return backend;
    }

    public HTTPAuthenticator getHttpAuthenticator() {
        return httpAuthenticator;
    }

    public int getOrder() {
        return order;
    }

    @Override
    public String toString() {
        return "AuthDomain [backend=" + backend + ", httpAuthenticator=" + httpAuthenticator + ", order=" + order + ", requirePreFlight="
                + requirePreFlight + "]";
    }

    @Override
    public int compareTo(final AuthDomain o) {
        return Integer.compare(this.order, o.order);
    }
}