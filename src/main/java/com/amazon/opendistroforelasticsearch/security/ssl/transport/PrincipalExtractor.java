/*
 * Copyright 2015-2017 floragunn GmbH
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

package com.amazon.opendistroforelasticsearch.security.ssl.transport;

import java.security.cert.X509Certificate;

public interface PrincipalExtractor {
    
    public enum Type {
        HTTP,
        TRANSPORT
    }

    /**
     * Extract the principal name
     * 
     * Please note that this method gets called for principal extraction of other nodes
     * as well as transport clients. It's up to the implementer to distinguish between them
     * and handle them appropriately.
     * 
     * Implementations must be public classes with a default public default constructor.
     * 
     * @param x509Certificate The first X509 certificate in the peer certificate chain
     *        This can be null, in this case the method must also return <code>null</code>.
     * @return The principal as string. This may be <code>null</code> in case where x509Certificate is null
     *        or the principal cannot be extracted because of any other circumstances.
     */
    String extractPrincipal(X509Certificate x509Certificate, Type type);

}
