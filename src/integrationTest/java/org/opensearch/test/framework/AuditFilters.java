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
import java.util.Collections;
import java.util.List;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

public class AuditFilters implements ToXContentObject {

    private Boolean enabledRest;

    private Boolean enabledTransport;

    private Boolean logRequestBody;

    private Boolean resolveIndices;

    private Boolean resolveBulkRequests;

    private Boolean excludeSensitiveHeaders;

    private List<String> ignoreUsers;

    private List<String> ignoreRequests;

    private List<String> ignoreHeaders;
    private List<String> ignoreUrlParams;

    private List<String> disabledRestCategories;

    private List<String> disabledTransportCategories;

    public AuditFilters() {
        this.enabledRest = false;
        this.enabledTransport = false;

        this.logRequestBody = true;
        this.resolveIndices = true;
        this.resolveBulkRequests = false;
        this.excludeSensitiveHeaders = true;

        this.ignoreUsers = Collections.emptyList();
        this.ignoreRequests = Collections.emptyList();
        this.ignoreHeaders = Collections.emptyList();
        this.ignoreUrlParams = Collections.emptyList();
        this.disabledRestCategories = Collections.emptyList();
        this.disabledTransportCategories = Collections.emptyList();
    }

    public AuditFilters enabledRest(boolean enabled) {
        this.enabledRest = enabled;
        return this;
    }

    public AuditFilters enabledTransport(boolean enabled) {
        this.enabledTransport = enabled;
        return this;
    }

    public AuditFilters logRequestBody(boolean logRequestBody) {
        this.logRequestBody = logRequestBody;
        return this;
    }

    public AuditFilters resolveIndices(boolean resolveIndices) {
        this.resolveIndices = resolveIndices;
        return this;
    }

    public AuditFilters resolveBulkRequests(boolean resolveBulkRequests) {
        this.resolveBulkRequests = resolveBulkRequests;
        return this;
    }

    public AuditFilters excludeSensitiveHeaders(boolean excludeSensitiveHeaders) {
        this.excludeSensitiveHeaders = excludeSensitiveHeaders;
        return this;
    }

    public AuditFilters ignoreUsers(List<String> ignoreUsers) {
        this.ignoreUsers = ignoreUsers;
        return this;
    }

    public AuditFilters ignoreRequests(List<String> ignoreRequests) {
        this.ignoreRequests = ignoreRequests;
        return this;
    }

    public AuditFilters ignoreHeaders(List<String> ignoreHeaders) {
        this.ignoreHeaders = ignoreHeaders;
        return this;
    }

    public AuditFilters ignoreUrlParams(List<String> ignoreUrlParams) {
        this.ignoreUrlParams = ignoreUrlParams;
        return this;
    }

    public AuditFilters disabledRestCategories(List<String> disabledRestCategories) {
        this.disabledRestCategories = disabledRestCategories;
        return this;
    }

    public AuditFilters disabledTransportCategories(List<String> disabledTransportCategories) {
        this.disabledTransportCategories = disabledTransportCategories;
        return this;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
        xContentBuilder.startObject();
        xContentBuilder.field("enable_rest", enabledRest);
        xContentBuilder.field("enable_transport", enabledTransport);
        xContentBuilder.field("resolve_indices", resolveIndices);
        xContentBuilder.field("log_request_body", logRequestBody);
        xContentBuilder.field("resolve_bulk_requests", resolveBulkRequests);
        xContentBuilder.field("exclude_sensitive_headers", excludeSensitiveHeaders);
        xContentBuilder.field("ignore_users", ignoreUsers);
        xContentBuilder.field("ignore_requests", ignoreRequests);
        xContentBuilder.field("ignore_headers", ignoreHeaders);
        xContentBuilder.field("ignore_url_params", ignoreUrlParams);
        xContentBuilder.field("disabled_rest_categories", disabledRestCategories);
        xContentBuilder.field("disabled_transport_categories", disabledTransportCategories);
        xContentBuilder.endObject();
        return xContentBuilder;
    }
}
