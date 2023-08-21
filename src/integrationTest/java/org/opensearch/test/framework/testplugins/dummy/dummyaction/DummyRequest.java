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
