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

public class AuditCompliance implements ToXContentObject {

    private boolean enabled = false;

    private Boolean writeLogDiffs;

    private List<String> readIgnoreUsers;

    private List<String> writeWatchedIndices;

    private List<String> writeIgnoreUsers;

    private Boolean readMetadataOnly;

    private Boolean writeMetadataOnly;

    private Boolean externalConfig;

    private Boolean internalConfig;

    public AuditCompliance enabled(boolean enabled) {
        this.enabled = enabled;
        this.writeLogDiffs = false;
        this.readIgnoreUsers = Collections.emptyList();
        this.writeWatchedIndices = Collections.emptyList();
        this.writeIgnoreUsers = Collections.emptyList();
        this.readMetadataOnly = false;
        this.writeMetadataOnly = false;
        this.externalConfig = false;
        this.internalConfig = false;
        return this;
    }

    public AuditCompliance writeLogDiffs(boolean writeLogDiffs) {
        this.writeLogDiffs = writeLogDiffs;
        return this;
    }

    public AuditCompliance readIgnoreUsers(List<String> list) {
        this.readIgnoreUsers = list;
        return this;
    }

    public AuditCompliance writeWatchedIndices(List<String> list) {
        this.writeWatchedIndices = list;
        return this;
    }

    public AuditCompliance writeIgnoreUsers(List<String> list) {
        this.writeIgnoreUsers = list;
        return this;
    }

    public AuditCompliance readMetadataOnly(boolean readMetadataOnly) {
        this.readMetadataOnly = readMetadataOnly;
        return this;
    }

    public AuditCompliance writeMetadataOnly(boolean writeMetadataOnly) {
        this.writeMetadataOnly = writeMetadataOnly;
        return this;
    }

    public AuditCompliance externalConfig(boolean externalConfig) {
        this.externalConfig = externalConfig;
        return this;
    }

    public AuditCompliance internalConfig(boolean internalConfig) {
        this.internalConfig = internalConfig;
        return this;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
        xContentBuilder.startObject();
        xContentBuilder.field("enabled", enabled);
        xContentBuilder.field("write_log_diffs", writeLogDiffs);
        xContentBuilder.field("read_ignore_users", readIgnoreUsers);
        xContentBuilder.field("write_watched_indices", writeWatchedIndices);
        xContentBuilder.field("write_ignore_users", writeIgnoreUsers);
        xContentBuilder.field("read_metadata_only", readMetadataOnly);
        xContentBuilder.field("write_metadata_only", writeMetadataOnly);
        xContentBuilder.field("external_config", externalConfig);
        xContentBuilder.field("internal_config", internalConfig);
        xContentBuilder.endObject();
        return xContentBuilder;
    }
}
