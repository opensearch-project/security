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

package com.amazon.opendistroforelasticsearch.security.http;

import java.net.InetSocketAddress;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.http.netty4.Netty4HttpRequest;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;

class RemoteIpDetector {

    /**
     * {@link Pattern} for a comma delimited string that support whitespace characters
     */
    private static final Pattern commaSeparatedValuesPattern = Pattern.compile("\\s*,\\s*");

    /**
     * Logger
     */
    protected final Logger log = LogManager.getLogger(this.getClass());

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
     * Convert an array of strings in a comma delimited string
     */
    protected static String listToCommaDelimitedString(List<String> stringList) {
        if (stringList == null) {
            return "";
        }
        StringBuilder result = new StringBuilder();
        for (Iterator<String> it = stringList.iterator(); it.hasNext();) {
            Object element = it.next();
            if (element != null) {
                result.append(element);
                if (it.hasNext()) {
                    result.append(", ");
                }
            }
        }
        return result.toString();
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
     * @see #setProxiesHeader(String)
     */
    private String proxiesHeader = "X-Forwarded-By";

    /**
     * @see #setRemoteIpHeader(String)
     */
    private String remoteIpHeader = "X-Forwarded-For";

    /**
     * @see RemoteIpValve#setTrustedProxies(String)
     */
    private Pattern trustedProxies = null;

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
     * @see #setProxiesHeader(String)
     * @return the proxies header name (e.g. "X-Forwarded-By")
     */
    public String getProxiesHeader() {
        return proxiesHeader;
    }

    /**
     * @see #setRemoteIpHeader(String)
     * @return the remote IP header name (e.g. "X-Forwarded-For")
     */
    public String getRemoteIpHeader() {
        return remoteIpHeader;
    }

    /**
     * @see #setTrustedProxies(String)
     * @return Regular expression that defines the trusted proxies
     */
    public String getTrustedProxies() {
        if (trustedProxies == null) {
            return null;
        }
        return trustedProxies.toString();
    }

    String detect(final Netty4HttpRequest request, ThreadContext threadContext){
        final String originalRemoteAddr = ((InetSocketAddress)request.getRemoteAddress()).getAddress().getHostAddress();
        @SuppressWarnings("unused")
        final String originalProxiesHeader = request.header(proxiesHeader);
        //final String originalRemoteIpHeader = request.getHeader(remoteIpHeader);
        
        if(log.isTraceEnabled()) {
            log.trace("originalRemoteAddr {}", originalRemoteAddr);
        }
        
        //X-Forwarded-For: client1, proxy1, proxy2
        //                                   ^^^^^^ originalRemoteAddr
        
        //originalRemoteAddr need to be in the list of internalProxies
        if (internalProxies !=null &&
                internalProxies.matcher(originalRemoteAddr).matches()) {
            String remoteIp = null;
            // In java 6, proxiesHeaderValue should be declared as a java.util.Deque
            final LinkedList<String> proxiesHeaderValue = new LinkedList<>();
            final StringBuilder concatRemoteIpHeaderValue = new StringBuilder();
            
            //client1, proxy1, proxy2
            final List<String> remoteIpHeaders = request.request().headers().getAll(remoteIpHeader); //X-Forwarded-For

            if(remoteIpHeaders == null || remoteIpHeaders.isEmpty()) {
                return originalRemoteAddr;
            }
            
            for (String rh:remoteIpHeaders) {
                if (concatRemoteIpHeaderValue.length() > 0) {
                    concatRemoteIpHeaderValue.append(", ");
                }

                concatRemoteIpHeaderValue.append(rh);
            }
            
            if(log.isTraceEnabled()) {
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
                } else if (trustedProxies != null &&
                        trustedProxies.matcher(currentRemoteIp).matches()) {
                    proxiesHeaderValue.addFirst(currentRemoteIp);
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

                if (proxiesHeaderValue.size() == 0) {
                    request.request().headers().remove(proxiesHeader);
                } else {
                    String commaDelimitedListOfProxies = listToCommaDelimitedString(proxiesHeaderValue);
                    request.request().headers().set(proxiesHeader,commaDelimitedListOfProxies);
                }
                if (newRemoteIpHeaderValue.size() == 0) {
                    request.request().headers().remove(remoteIpHeader);
                } else {
                    String commaDelimitedRemoteIpHeaderValue = listToCommaDelimitedString(newRemoteIpHeaderValue);
                    request.request().headers().set(remoteIpHeader,commaDelimitedRemoteIpHeaderValue);
                }
                
                if (log.isTraceEnabled()) {
                    final String originalRemoteHost = ((InetSocketAddress)request.getRemoteAddress()).getAddress().getHostName();
                    log.trace("Incoming request " + request.request().uri() + " with originalRemoteAddr '" + originalRemoteAddr
                              + "', originalRemoteHost='" + originalRemoteHost + "', will be seen as newRemoteAddr='" + remoteIp);
                }
                
                //TODO check put in thread context
                threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_XFF_DONE, Boolean.TRUE);
                //request.putInContext(ConfigConstants.OPENDISTRO_SECURITY_XFF_DONE, Boolean.TRUE);
                return remoteIp;
                
            } else {
                log.warn("Remote ip could not be detected, this should normally not happen");
            }
            
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Skip RemoteIpDetector for request " + request.request().uri() + " with originalRemoteAddr '"
                        + request.getRemoteAddress() + "' cause no internal proxy matches");
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
     * The proxiesHeader directive specifies a header into which mod_remoteip will collect a list of all of the intermediate client IP
     * addresses trusted to resolve the actual remote IP. Note that intermediate RemoteIPTrustedProxy addresses are recorded in this header,
     * while any intermediate RemoteIPInternalProxy addresses are discarded.
     * </p>
     * <p>
     * Name of the http header that holds the list of trusted proxies that has been traversed by the http request.
     * </p>
     * <p>
     * The value of this header can be comma delimited.
     * </p>
     * <p>
     * Default value : <code>X-Forwarded-By</code>
     * </p>
     */
    public void setProxiesHeader(String proxiesHeader) {
        this.proxiesHeader = proxiesHeader;
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

    /**
     * <p>
     * Regular expression defining proxies that are trusted when they appear in
     * the {@link #remoteIpHeader} header.
     * </p>
     * <p>
     * Default value : empty list, no external proxy is trusted.
     * </p>
     */
    public void setTrustedProxies(String trustedProxies) {
        if (trustedProxies == null || trustedProxies.length() == 0) {
            this.trustedProxies = null;
        } else {
            this.trustedProxies = Pattern.compile(trustedProxies);
        }
    }
}
