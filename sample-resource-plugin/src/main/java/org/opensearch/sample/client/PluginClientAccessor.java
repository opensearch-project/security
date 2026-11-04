/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.client;

import org.opensearch.sample.utils.PluginClient;

/**
 * Accessor for this plugin's system-subject client, for the components the SPI loads itself and so cannot be given one
 * through a constructor, such as the gating resource resolver.
 */
public class PluginClientAccessor {

    private static PluginClient CLIENT;

    private PluginClientAccessor() {}

    public static void setPluginClient(PluginClient client) {
        CLIENT = client;
    }

    public static PluginClient getPluginClient() {
        return CLIENT;
    }
}
