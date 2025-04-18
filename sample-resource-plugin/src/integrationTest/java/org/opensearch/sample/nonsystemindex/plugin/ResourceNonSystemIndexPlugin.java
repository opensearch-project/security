/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.nonsystemindex.plugin;

import java.nio.file.Path;

import org.opensearch.common.settings.Settings;
import org.opensearch.plugins.Plugin;

/**
 * Sample resource sharing plugin that doesn't declare its resource index as system index.
 * TESTING ONLY
 */
public class ResourceNonSystemIndexPlugin extends Plugin {
    public static final String SAMPLE_NON_SYSTEM_INDEX_NAME = "sample_non_system_index";

    public ResourceNonSystemIndexPlugin(final Settings settings, final Path path) {}

}
