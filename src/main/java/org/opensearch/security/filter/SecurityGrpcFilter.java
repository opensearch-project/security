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
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.filter;

import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.transport.grpc.spi.GrpcInterceptorProvider;

import java.util.List;

public class SecurityGrpcFilter implements GrpcInterceptorProvider {

    static {
        System.out.println("SecurityGrpcFilter - class loaded by ClassLoader: " + SecurityGrpcFilter.class.getClassLoader());
    }

    public SecurityGrpcFilter() {
        System.out.println("SecurityGrpcFilter - constructor called - interceptor provider is being instantiated");
    }

    @Override
    public List<OrderedGrpcInterceptor> getOrderedGrpcInterceptors(ThreadContext threadContext) {
        System.out.println("SecurityGrpcFilter - getOrderedGrpcInterceptors called - returning security interceptor");
        return List.of(new OrderedGrpcInterceptor() {

            @Override
            public int order() {
                return 0;
            }

            @Override
            public ServerInterceptor getInterceptor() {
                return new ServerInterceptor() {
                    @Override
                    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> serverCall, Metadata metadata, ServerCallHandler<ReqT, RespT> serverCallHandler) {
                        System.out.println("SecurityGrpcFilter - Interceptor called");
                        return serverCallHandler.startCall(serverCall, metadata);
                    }
                };
            }
        });
    }
}
