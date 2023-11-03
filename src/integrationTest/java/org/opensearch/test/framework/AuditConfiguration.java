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

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

public class AuditConfiguration implements ToXContentObject {
    private final boolean enabled;

    private AuditFilters filters;

    private AuditCompliance compliance;

    public AuditConfiguration(boolean enabled) {
        this.filters = new AuditFilters();
        this.compliance = new AuditCompliance();
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public AuditConfiguration filters(AuditFilters filters) {
        this.filters = filters;
        return this;
    }

    public AuditConfiguration compliance(AuditCompliance auditCompliance) {
        this.compliance = auditCompliance;
        return this;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
        // json built here must be deserialized to org.opensearch.security.auditlog.config.AuditConfig
        xContentBuilder.startObject();
        xContentBuilder.field("enabled", enabled);

        xContentBuilder.field("audit", filters);
        xContentBuilder.field("compliance", compliance);

        xContentBuilder.endObject();
        return xContentBuilder;
    }
}
