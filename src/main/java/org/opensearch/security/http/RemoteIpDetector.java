/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
 * Portions Copyright OpenSearch Contributors
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

package org.opensearch.security.http;

import java.net.InetSocketAddress;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Pattern;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.rest.RestRequest;

import org.opensearch.security.support.ConfigConstants;

final class RemoteIpDetector {

    /**
     * {@link Pattern} for a comma delimited string that support whitespace characters
     */
    private static final Pattern commaSeparatedValuesPattern = Pattern.compile("\\s*,\\s*");

    /**
     * Logger
     */
    protected final Logger log = LoggerFactory.getLogger(this.getClass());

    /**
     * Convert a given comma delimited String into an array of String
     *
     * @return array of String (non <code>null</code>)
     */
    protected static String[] commaDelimitedListToStringArray(String commaDelimitedStrings) {
        return (commaDelimitedStrings == null || commaDelimitedStrings.length() == 0) ? new String[0] : commaSeparatedValuesPattern
            .split(commaDelimitedStrings);
    }

    /**
     * @see #setInternalProxies(String)
     */
    private Pattern internalProxies = Pattern.compile(
            "10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|" +
            "192\\.168\\.\\d{1,3}\\.\\d{1,3}|" +
            "169\\.254\\.\\d{1,3}\\.\\d{1,3}|" +
            "127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|" +
            "172\\.1[6-9]{1}\\.\\d{1,3}\\.\\d{1,3}|" +
            "172\\.2[0-9]{1}\\.\\d{1,3}\\.\\d{1,3}|" +
            "172\\.3[0-1]{1}\\.\\d{1,3}\\.\\d{1,3}");

    /**
     * @see #setRemoteIpHeader(String)
     */
    private String remoteIpHeader = "X-Forwarded-For";

    /**
     * @see #setInternalProxies(String)
     * @return Regular expression that defines the internal proxies
     */
    public String getInternalProxies() {
        if (internalProxies == null) {
            return null;
        }
        return internalProxies.toString();
    }

    /**
     * @see #setRemoteIpHeader(String)
     * @return the remote IP header name (e.g. "X-Forwarded-For")
     */
    public String getRemoteIpHeader() {
        return remoteIpHeader;
    }

    String detect(RestRequest request, ThreadContext threadContext){
        final String originalRemoteAddr = ((InetSocketAddress)request.getHttpChannel().getRemoteAddress()).getAddress().getHostAddress();

        final boolean isTraceEnabled = log.isTraceEnabled();
        if (isTraceEnabled) {
            log.trace("originalRemoteAddr {}", originalRemoteAddr);
        }
        
        //X-Forwarded-For: client1, proxy1, proxy2
        //                                   ^^^^^^ originalRemoteAddr
        
        //originalRemoteAddr need to be in the list of internalProxies
        if (internalProxies !=null &&
                internalProxies.matcher(originalRemoteAddr).matches()) {
            String remoteIp = null;
            final StringBuilder concatRemoteIpHeaderValue = new StringBuilder();
            
            //client1, proxy1, proxy2
            final List<String> remoteIpHeaders = request.getHeaders().get(remoteIpHeader); //X-Forwarded-For

            if(remoteIpHeaders == null || remoteIpHeaders.isEmpty()) {
                return originalRemoteAddr;
            }
            
            for (String rh:remoteIpHeaders) {
                if (concatRemoteIpHeaderValue.length() > 0) {
                    concatRemoteIpHeaderValue.append(", ");
                }

                concatRemoteIpHeaderValue.append(rh);
            }
            
            if (isTraceEnabled) {
                log.trace("concatRemoteIpHeaderValue {}", concatRemoteIpHeaderValue.toString());
            }

            final String[] remoteIpHeaderValue = commaDelimitedListToStringArray(concatRemoteIpHeaderValue.toString());
            int idx;
            // loop on remoteIpHeaderValue to find the first trusted remote ip and to build the proxies chain
            for (idx = remoteIpHeaderValue.length - 1; idx >= 0; idx--) {
                String currentRemoteIp = remoteIpHeaderValue[idx];
                remoteIp = currentRemoteIp;
                if (internalProxies.matcher(currentRemoteIp).matches()) {
                    // do nothing, internalProxies IPs are not appended to the
                } else {
                    idx--; // decrement idx because break statement doesn't do it
                    break;
                }
            }
            
            // continue to loop on remoteIpHeaderValue to build the new value of the remoteIpHeader
            final LinkedList<String> newRemoteIpHeaderValue = new LinkedList<>();
            for (; idx >= 0; idx--) {
                String currentRemoteIp = remoteIpHeaderValue[idx];
                newRemoteIpHeaderValue.addFirst(currentRemoteIp);
            }
            
            if (remoteIp != null) {
                if (isTraceEnabled) {
                    final String originalRemoteHost = ((InetSocketAddress)request.getHttpChannel().getRemoteAddress()).getAddress().getHostName();
                    log.trace("Incoming request {} with originalRemoteAddr '{}', originalRemoteHost='{}', will be seen as newRemoteAddr='{}'", request.uri(), originalRemoteAddr, originalRemoteHost, remoteIp);
                }

                threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_XFF_DONE, Boolean.TRUE);
                return remoteIp;
                
            } else {
                log.warn("Remote ip could not be detected, this should normally not happen");
            }
            
        } else {
            if (isTraceEnabled) {
                log.trace("Skip RemoteIpDetector for request {} with originalRemoteAddr '{}' cause no internal proxy matches", request.uri(), request.getHttpChannel().getRemoteAddress());
            }
        }
        
        return originalRemoteAddr;
    }

    /**
     * <p>
     * Regular expression that defines the internal proxies.
     * </p>
     * <p>
     * Default value : 10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|169\.254.\d{1,3}.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}
     * </p>
     */
    public void setInternalProxies(String internalProxies) {
        if (internalProxies == null || internalProxies.length() == 0) {
            this.internalProxies = null;
        } else {
            this.internalProxies = Pattern.compile(internalProxies);
        }
    }

    /**
     * <p>
     * Name of the http header from which the remote ip is extracted.
     * </p>
     * <p>
     * The value of this header can be comma delimited.
     * </p>
     * <p>
     * Default value : <code>X-Forwarded-For</code>
     * </p>
     *
     * @param remoteIpHeader
     */
    public void setRemoteIpHeader(String remoteIpHeader) {
        this.remoteIpHeader = remoteIpHeader;
    }
}
