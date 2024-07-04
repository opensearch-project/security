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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import org.junit.Test;

import org.opensearch.OpenSearchException;

public class StreamableRegistryTest {

    StreamableRegistry streamableRegistry = StreamableRegistry.getInstance();

    @Test
    public void testStreamableTypeIDs() {
        assertThat(streamableRegistry.getStreamableID(InetSocketAddress.class), is(1));
        Assert.assertThrows(OpenSearchException.class, () -> streamableRegistry.getStreamableID(String.class));
    }
}
