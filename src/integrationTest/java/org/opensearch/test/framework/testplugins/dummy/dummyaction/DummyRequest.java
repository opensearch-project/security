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

package org.opensearch.test.framework.testplugins.dummy.dummyaction;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;

public class DummyRequest extends ActionRequest implements ToXContent {

    private final String message;

    public DummyRequest(final StreamInput in) throws IOException {
        super(in);
        message = in.readString();
    }

    public DummyRequest(String message) {
        this.message = message;
    }

    /**
     * @return
     */
    @Override
    public ActionRequestValidationException validate() {
        // if (Strings.isNullOrEmpty(message)) {
        // ActionRequestValidationException ex = new ActionRequestValidationException();
        // ex.addValidationError("Message cannot be null or empty");
        // throw ex;
        // }
        return null;
    }

    /**
     * @param xContentBuilder
     * @param params
     * @return
     * @throws IOException
     */
    @Override
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
        xContentBuilder.field("message", message);

        return xContentBuilder;
    }
}
