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

// CS-SUPPRESS-SINGLE: RegexpSingleline It is not possible to use phrase "cluster manager" instead of master here
import java.io.IOException;

import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
// CS-ENFORCE-SINGLE

public class RunClusterHealthResponse extends AcknowledgedResponse implements ToXContentObject {

    public RunClusterHealthResponse(boolean status) {
        super(status);
    }

    public RunClusterHealthResponse(StreamInput in) throws IOException {
        super(in);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
    }

    @Override
    public void addCustomFields(XContentBuilder builder, Params params) throws IOException {
        super.addCustomFields(builder, params);
    }
}
