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

import org.junit.Assert;
import org.junit.Test;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import org.opensearch.OpenSearchException;

import java.net.InetSocketAddress;

public class StreamableRegistryTest {

    StreamableRegistry streamableRegistry = StreamableRegistry.getInstance();

    @Test
    public void testStreamableTypeIDs() {
        assertThat(streamableRegistry.getStreamableID(InetSocketAddress.class), is(1));
        Assert.assertThrows(OpenSearchException.class, () -> streamableRegistry.getStreamableID(String.class));
    }
}
