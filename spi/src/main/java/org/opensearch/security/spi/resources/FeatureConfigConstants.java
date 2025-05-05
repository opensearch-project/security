/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

public class FeatureConfigConstants {
    // Resource sharing feature-flag
    public static final String OPENSEARCH_RESOURCE_SHARING_ENABLED = "plugins.security.experimental.resource_sharing.enabled";
    public static final boolean OPENSEARCH_RESOURCE_SHARING_ENABLED_DEFAULT = false;
}
