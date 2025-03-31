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

package org.opensearch.sample;

import java.io.IOException;

import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.security.spi.resources.ShareableResourceParser;

/**
 * Responsible for parsing the XContent into a SampleResource object.
 */
public class SampleResourceParser implements ShareableResourceParser<SampleResource> {
    @Override
    public SampleResource parseXContent(XContentParser parser) throws IOException {
        return SampleResource.fromXContent(parser);
    }
}
