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

package org.opensearch.security.support;

import java.net.InetSocketAddress;

import org.junit.Assert;
import org.junit.Test;

import org.opensearch.OpenSearchException;

public class StreamableRegistryTest {

    StreamableRegistry streamableRegistry = StreamableRegistry.getInstance();

    @Test
    public void testStreamableTypeIDs() {
        Assert.assertEquals(1, streamableRegistry.getStreamableID(InetSocketAddress.class));
        Assert.assertThrows(OpenSearchException.class, () -> streamableRegistry.getStreamableID(String.class));
    }
}
