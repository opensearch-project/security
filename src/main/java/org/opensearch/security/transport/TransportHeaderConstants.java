/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.transport;

import java.util.Set;

import org.opensearch.security.support.ConfigConstants;

final class TransportHeaderConstants {

    static final String ACTION_TRACE_HEADER_PREFIX = "_opendistro_security_trace";
    static final String SOURCE_FIELD_CONTEXT_HEADER = ConfigConstants.OPENDISTRO_SECURITY_SOURCE_FIELD_CONTEXT;
    static final Set<String> SECURITY_HEADERS_TO_COPY = Set.of(
        ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER,
        ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER,
        ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS_HEADER,
        ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER,
        ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER_HEADER,
        ConfigConstants.OPENDISTRO_SECURITY_USER_SAME_AS_SUBJECT_HEADER,
        ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_HEADER,
        ConfigConstants.OPENDISTRO_SECURITY_FLS_FIELDS_HEADER,
        ConfigConstants.OPENDISTRO_SECURITY_MASKED_FIELD_HEADER,
        ConfigConstants.OPENDISTRO_SECURITY_DOC_ALLOWLIST_HEADER,
        ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE,
        ConfigConstants.OPENDISTRO_SECURITY_DLS_QUERY_FILTER_APPLIED,
        ConfigConstants.OPENDISTRO_SECURITY_DLS_MODE_HEADER,
        ConfigConstants.OPENDISTRO_SECURITY_DLS_FILTER_LEVEL_QUERY_HEADER,
        ConfigConstants.OPENSEARCH_SECURITY_REQUEST_HEADERS
    );

    private TransportHeaderConstants() {}
}
