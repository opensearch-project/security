/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security.plugin;

import java.io.IOException;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;

public class IndexDocumentIntoSystemIndexRequest extends ActionRequest {

    private final String indexName;

    private final String runAs;

    public IndexDocumentIntoSystemIndexRequest(String indexName, String runAs) {
        this.indexName = indexName;
        this.runAs = runAs;
    }

    public IndexDocumentIntoSystemIndexRequest(StreamInput in) throws IOException {
        super(in);
        this.indexName = in.readString();
        this.runAs = in.readOptionalString();
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public String getIndexName() {
        return this.indexName;
    }

    public String getRunAs() {
        return this.runAs;
    }
}
