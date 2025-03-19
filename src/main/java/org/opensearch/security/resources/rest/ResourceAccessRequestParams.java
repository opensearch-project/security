/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.rest;

import java.io.IOException;

import org.opensearch.core.common.io.stream.NamedWriteable;
import org.opensearch.core.common.io.stream.StreamOutput;

/**
 * This class is used to represent the request parameters for resource access.
 * It implements the NamedWriteable interface to allow serialization and deserialization of the request parameters.
 *
 * @opensearch.experimental
 */
public class ResourceAccessRequestParams implements NamedWriteable {
    @Override
    public String getWriteableName() {
        return "resource_access_request_params";
    }

    @Override
    public void writeTo(StreamOutput streamOutput) throws IOException {

    }
}
