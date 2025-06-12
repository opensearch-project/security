/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.actions.rest.share;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.DocRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.security.spi.resources.sharing.Recipient;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Request object for sharing sample resource transport action
 */
public class ShareResourceRequest extends ActionRequest implements DocRequest {

    private final String resourceId;

    private final Map<Recipient, Set<String>> recipients;

    public ShareResourceRequest(String resourceId, Map<Recipient, Set<String>> recipients) {
        this.resourceId = resourceId;
        this.recipients = recipients;
    }

    public ShareResourceRequest(StreamInput in) throws IOException {
        this.resourceId = in.readString();
        this.recipients = in.readMap(key -> key.readEnum(Recipient.class), input -> input.readSet(StreamInput::readString));
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(this.resourceId);
        out.writeMap(
            recipients,
            StreamOutput::writeEnum,
            (streamOutput, strings) -> streamOutput.writeCollection(strings, StreamOutput::writeString)
        );
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public String getResourceId() {
        return this.resourceId;
    }

    public Map<Recipient, Set<String>> getRecipients() {
        return recipients;
    }

    @Override
    public String index() {
        return RESOURCE_INDEX_NAME;
    }

    @Override
    public String id() {
        return resourceId;
    }
}
