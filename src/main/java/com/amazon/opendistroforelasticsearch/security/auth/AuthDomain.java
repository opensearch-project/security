/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.auth;

import java.util.Objects;

public class AuthDomain implements Comparable<AuthDomain> {

    private final AuthenticationBackend backend;
    private final HTTPAuthenticator httpAuthenticator;
    private final int order;
    private final boolean challenge;

    public AuthDomain(final AuthenticationBackend backend, final HTTPAuthenticator httpAuthenticator, boolean challenge, final int order) {
        super();
        this.backend = Objects.requireNonNull(backend);
        this.httpAuthenticator = httpAuthenticator;
        this.order = order;
        this.challenge = challenge;
    }

    public boolean isChallenge() {
        return challenge;
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
        return "AuthDomain [backend=" + backend + ", httpAuthenticator=" + httpAuthenticator + ", order=" + order + ", challenge="
                + challenge + "]";
    }

    @Override
    public int compareTo(final AuthDomain o) {
        return Integer.compare(this.order, o.order);
    }
}