/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.common.resources.rest;

import java.io.IOException;

import org.opensearch.core.common.io.stream.NamedWriteable;
import org.opensearch.core.common.io.stream.StreamOutput;

public class ResourceAccessRequestParams implements NamedWriteable {
    @Override
    public String getWriteableName() {
        return "resource_access_request_params";
    }

    @Override
    public void writeTo(StreamOutput streamOutput) throws IOException {

    }
}
