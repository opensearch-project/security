/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.http;

import java.util.Collection;
import java.util.Collections;

import org.opensearch.common.settings.Settings;
import org.opensearch.indices.SystemIndexDescriptor;
import org.opensearch.plugins.Plugin;
import org.opensearch.plugins.SystemIndexPlugin;

public class ExampleSystemIndexPlugin extends Plugin implements SystemIndexPlugin {

    @Override
    public Collection<SystemIndexDescriptor> getSystemIndexDescriptors(Settings settings) {
        final SystemIndexDescriptor systemIndexDescriptor = new SystemIndexDescriptor(".system-index1", "System index 1");
        return Collections.singletonList(systemIndexDescriptor);
    }
}
