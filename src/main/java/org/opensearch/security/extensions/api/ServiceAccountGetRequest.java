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

package org.opensearch.security.extensions.api;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.nodes.BaseNodesRequest;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;

import java.io.IOException;

public class ServiceAccountGetRequest extends ActionRequest {

    private String extensionId;

    public ServiceAccountGetRequest(StreamInput in) throws IOException {
        this.extensionId = in.readString();
    }

    public ServiceAccountGetRequest() {
        super();
    }

    public ServiceAccountGetRequest(String extensionId) {
        this();
        setExtensionId(extensionId);
    }


    public void writeTo(final StreamOutput out) throws IOException {
        out.writeStringArray(extensionId.split(""));
    }

    public String getExtensionId() {
        return extensionId;
    }

    public void setExtensionId(final String extensionId) {
        this.extensionId = extensionId;
    }

    public ActionRequestValidationException validate() {
        if (extensionId == null || extensionId.length() == 0) {
            return new ActionRequestValidationException();
        }
        return null;
    }
}

