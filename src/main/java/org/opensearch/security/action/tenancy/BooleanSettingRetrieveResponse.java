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

package org.opensearch.security.action.tenancy;

import java.io.IOException;

import org.opensearch.action.ActionResponse;
import org.opensearch.common.Strings;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

public class BooleanSettingRetrieveResponse extends ActionResponse implements ToXContentObject {
    
    private Boolean value;
    
    public BooleanSettingRetrieveResponse(final StreamInput in) throws IOException {
        super(in);
        this.value = in.readBoolean();
    }

    public BooleanSettingRetrieveResponse(final Boolean value) {
        this.value = value;
    }

    public Boolean getValue() {
        return value;
    }
    
    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeBoolean(getValue());
    }

    @Override
    public String toString() {
        return Strings.toString(XContentType.JSON, this, true, true);
    }

    @Override
    public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
        builder.startObject();
        builder.field("value", getValue());
        builder.endObject();
        return builder;
    }
}
