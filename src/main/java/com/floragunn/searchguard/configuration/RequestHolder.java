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

package com.floragunn.searchguard.configuration;

import java.util.Objects;

import org.elasticsearch.transport.TransportRequest;

public class RequestHolder {
    private static final ThreadLocal<RequestHolder> current = new ThreadLocal<RequestHolder>();
    private final TransportRequest request;

    public static RequestHolder current() {
        return current.get();
    }

    public static void setCurrent(final RequestHolder value) {
        current.set(Objects.requireNonNull(value));
    }

    public static void removeCurrent() {
        current.remove();
    }

    public RequestHolder(final TransportRequest request) {
        this.request = Objects.requireNonNull(request);
    }

    public TransportRequest getRequest() {
        return this.request;
    }

    @Override
    public String toString() {
        return "RequestHolder [request=" + request==null?null:request.getContext() + "]";
    }
}
