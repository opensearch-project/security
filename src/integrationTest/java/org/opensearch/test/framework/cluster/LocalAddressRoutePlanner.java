/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework.cluster;

import java.net.InetAddress;
import java.util.Objects;

import org.apache.hc.client5.http.impl.DefaultSchemePortResolver;
import org.apache.hc.client5.http.impl.routing.DefaultRoutePlanner;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.protocol.HttpContext;

/**
* Class which can be used to bind Apache HTTP client to a particular network interface or its IP address so that the IP address of
* network interface is used as a source IP address of HTTP request.
*/
class LocalAddressRoutePlanner extends DefaultRoutePlanner {

    /**
    * IP address of one of the local network interfaces.
    */
    private final InetAddress localAddress;

    /**
    * Creates {@link LocalAddressRoutePlanner}
    * @param localAddress IP address of one of the local network interfaces. Client socket used by Apache HTTP client will be bind to
    *                        address from this parameter. The parameter must not be <code>null</code>.
    */
    public LocalAddressRoutePlanner(InetAddress localAddress) {
        super(DefaultSchemePortResolver.INSTANCE);
        this.localAddress = Objects.requireNonNull(localAddress);
    }

    /**
    * Determines IP address used by the client socket of Apache HTTP client
    */
    @Override
    protected InetAddress determineLocalAddress(HttpHost firstHop, HttpContext context) {
        return localAddress;
    }
}
