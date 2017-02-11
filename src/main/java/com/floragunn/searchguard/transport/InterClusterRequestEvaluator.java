/*
 * Copyright 2017 floragunn UG (haftungsbeschränkt)
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
package com.floragunn.searchguard.transport;

import java.security.cert.X509Certificate;

import org.elasticsearch.transport.TransportRequest;

/**
 * Evaluates a request to determine if it is
 * intercluster communication.  Implementations
 * should include a single arg constructor that
 * takes org.elasticsearch.common.settings.Settings
 *
 */
public interface InterClusterRequestEvaluator {

    /**
     * Determine if request is a message from
     * another node in the cluster
     * 
     * @param   request     The transport request to evaluate
     * @param   localCerts  Local certs to use for evaluating the request which include criteria
     *                      specific to the implementation for confirming intercluster
     *                      communication
     *                      
     * @param   peerCerts       Certs to use for evaluating the request which include criteria
     *                      specific to the implementation for confirming intercluster
     *                      communication
     *                      
     * @param principal    The principal evaluated by the configured principal extractor
     *                      
     * @return True when determined to be intercluster, false otherwise
     */
    boolean isInterClusterRequest(final TransportRequest request, final X509Certificate[] localCerts, final X509Certificate[] peerCerts,
            final String principal);
}
