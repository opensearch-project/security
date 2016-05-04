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

package com.floragunn.searchguard.support;

import java.io.Serializable;
import java.util.Map.Entry;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.transport.TransportMessage;
import org.elasticsearch.transport.TransportRequest;

import com.google.common.base.Strings;

public class HeaderHelper {

    public static void checkSGHeader(final RestRequest request) {
        if (request != null) {

            for (final String header : request.getHeaders()) {
                if (header != null && header.trim().toLowerCase().startsWith(ConfigConstants.SG_CONFIG_PREFIX.toLowerCase())) {
                    throw new ElasticsearchSecurityException("invalid header found");
                }
            }

            for (final Entry<String, String> header : request.headers()) {
                if (header != null && header.getKey() != null
                        && header.getKey().trim().toLowerCase().startsWith(ConfigConstants.SG_CONFIG_PREFIX.toLowerCase())) {
                    throw new ElasticsearchSecurityException("invalid header found");
                }
            }
        }
    }

    public static void checkSGHeader(final TransportMessage<?> request) {
        if (request != null) {
            for (final String header : request.getHeaders()) {
                if (header != null && header.trim().toLowerCase().startsWith(ConfigConstants.SG_CONFIG_PREFIX.toLowerCase())) {
                    throw new ElasticsearchSecurityException("invalid header found");
                }
            }
        }
    }

    public static boolean isInterClusterRequest(final TransportRequest request) {
        return request.getFromContext(ConfigConstants.SG_SSL_TRANSPORT_INTERCLUSTER_REQUEST) == Boolean.TRUE;
    }

    public static boolean isDirectRequest(final TransportRequest request) {
        return "direct".equals(request.getFromContext(ConfigConstants.SG_CHANNEL_TYPE)) || request.remoteAddress() == null;
    }

    public static String getSafeFromHeader(final TransportRequest request, final String headerName) {

        if (request == null || headerName == null || headerName.isEmpty()) {
            return null;
        }

        String headerValue = null;

        if (!request.hasHeader(headerName) || (headerValue = request.getHeader(headerName)) == null) {
            return null;
        }

        if (isInterClusterRequest(request) || isDirectRequest(request)) {
            return headerValue;
        }

        return null;
    }

    public static Serializable deserializeSafeFromHeader(final TransportRequest request, final String headerName) {

        final String objectAsBase64 = getSafeFromHeader(request, headerName);

        if (!Strings.isNullOrEmpty(objectAsBase64)) {
            return Base64Helper.deserializeObject(objectAsBase64);
        }

        return null;
    }

}
