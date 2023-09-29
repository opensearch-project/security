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

package org.opensearch.security.support;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;

import com.google.common.base.Strings;

import org.opensearch.common.util.concurrent.ThreadContext;

public class HeaderHelper {

    public static boolean isInterClusterRequest(final ThreadContext context) {
        return context.getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_INTERCLUSTER_REQUEST) == Boolean.TRUE;
    }

    public static boolean isDirectRequest(final ThreadContext context) {

        return "direct".equals(context.getTransient(ConfigConstants.OPENDISTRO_SECURITY_CHANNEL_TYPE))
            || context.getTransient(ConfigConstants.OPENDISTRO_SECURITY_CHANNEL_TYPE) == null;
    }

    public static boolean isExtensionRequest(final ThreadContext context) {
        return context.getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_EXTENSION_REQUEST) == Boolean.TRUE;
    }

    public static String getSafeFromHeader(final ThreadContext context, final String headerName) {

        if (context == null || headerName == null || headerName.isEmpty()) {
            return null;
        }

        if (isInterClusterRequest(context) || isTrustedClusterRequest(context) || isDirectRequest(context)) {
            return context.getHeader(headerName);
        }

        return null;
    }

    public static Serializable deserializeSafeFromHeader(final ThreadContext context, final String headerName) {

        final String objectAsBase64 = getSafeFromHeader(context, headerName);

        if (!Strings.isNullOrEmpty(objectAsBase64)) {
            return Base64Helper.deserializeObject(objectAsBase64, context.getTransient(ConfigConstants.USE_JDK_SERIALIZATION));
        }

        return null;
    }

    public static boolean isTrustedClusterRequest(final ThreadContext context) {
        return context.getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTED_CLUSTER_REQUEST) == Boolean.TRUE;
    }

    public static List<String> getAllSerializedHeaderNames() {
        return Arrays.asList(
            ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS_HEADER,
            ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER,
            ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER,
            ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER,
            ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER,
            ConfigConstants.OPENDISTRO_SECURITY_DLS_FILTER_LEVEL_QUERY_HEADER,
            ConfigConstants.OPENDISTRO_SECURITY_SOURCE_FIELD_CONTEXT
        );
    }
}
