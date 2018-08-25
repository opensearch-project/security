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

package com.floragunn.searchguard.support;

import java.io.Serializable;
import java.util.Map;

import org.elasticsearch.common.util.concurrent.ThreadContext;

import com.google.common.base.Strings;

public class HeaderHelper {

    public static boolean isInterClusterRequest(final ThreadContext context) {
        return context.getTransient(ConfigConstants.SG_SSL_TRANSPORT_INTERCLUSTER_REQUEST) == Boolean.TRUE;
    }

    public static boolean isDirectRequest(final ThreadContext context) {
        
        return  "direct".equals(context.getTransient(ConfigConstants.SG_CHANNEL_TYPE))
                  || context.getTransient(ConfigConstants.SG_CHANNEL_TYPE) == null;
    }
    
    
    public static String getSafeFromHeader(final ThreadContext context, final String headerName) {

        if (context == null || headerName == null || headerName.isEmpty()) {
            return null;
        }

        String headerValue = null;
        	
        Map<String, String> headers = context.getHeaders();
        if (!headers.containsKey(headerName) || (headerValue = headers.get(headerName)) == null) {
            return null;
        }

        if (isInterClusterRequest(context) || isTrustedClusterRequest(context) || isDirectRequest(context)) {
            return headerValue;
        }

        return null;
    }

    public static Serializable deserializeSafeFromHeader(final ThreadContext context, final String headerName) {

        final String objectAsBase64 = getSafeFromHeader(context, headerName);

        if (!Strings.isNullOrEmpty(objectAsBase64)) {
            return Base64Helper.deserializeObject(objectAsBase64);
        }

        return null;
    }
    
    public static boolean isTrustedClusterRequest(final ThreadContext context) {
        return context.getTransient(ConfigConstants.SG_SSL_TRANSPORT_TRUSTED_CLUSTER_REQUEST) == Boolean.TRUE;
    }
}
