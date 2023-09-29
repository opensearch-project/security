/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework;

import java.io.IOException;

import org.apache.commons.lang3.StringUtils;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

/**
* <p>
* XFF is an abbreviation of <code>X-Forwarded-For</code>. X-Forwarded-For is an HTTP header which contains client source IP address
* and additionally IP addresses of proxies which forward the request.
* The X-Forwarded-For header is used by HTTP authentication of type
* </p>
* <ol>
*     <li><code>proxy</code> defined by class {@link org.opensearch.security.http.HTTPProxyAuthenticator}</li>
*     <li><code>extended-proxy</code> defined by the class {@link org.opensearch.security.http.proxy.HTTPExtendedProxyAuthenticator}</li>
* </ol>
*
* <p>
* The above authenticators use the X-Forwarded-For to determine if an HTTP request comes from trusted proxies. The trusted proxies
* are defined by a regular expression {@link #internalProxiesRegexp}. The proxy authentication can be applied only to HTTP requests
* which were forwarded by trusted HTTP proxies.
* </p>
*
*<p>
*     The class can be serialized to JSON and then stored in an OpenSearch index which contains security plugin configuration.
*</p>
*/
public class XffConfig implements ToXContentObject {

    private final boolean enabled;

    /**
    * Regular expression used to determine if HTTP proxy is trusted or not. IP address of trusted proxies must match the regular
    * expression defined by the below field.
    */
    private String internalProxiesRegexp;

    private String remoteIpHeader;

    public XffConfig(boolean enabled) {
        this.enabled = enabled;
    }

    /**
    * Builder-like method used to set value of the field {@link #internalProxiesRegexp}
    * @param internalProxiesRegexp regular expression which matches IP address of a HTTP proxies if the proxies are trusted.
    * @return builder
    */
    public XffConfig internalProxiesRegexp(String internalProxiesRegexp) {
        this.internalProxiesRegexp = internalProxiesRegexp;
        return this;
    }

    public XffConfig remoteIpHeader(String remoteIpHeader) {
        this.remoteIpHeader = remoteIpHeader;
        return this;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
        xContentBuilder.startObject();
        xContentBuilder.field("enabled", enabled);
        xContentBuilder.field("internalProxies", internalProxiesRegexp);
        if (StringUtils.isNoneBlank(remoteIpHeader)) {
            xContentBuilder.field("remoteIpHeader", remoteIpHeader);
        }
        xContentBuilder.endObject();
        return xContentBuilder;
    }
}
