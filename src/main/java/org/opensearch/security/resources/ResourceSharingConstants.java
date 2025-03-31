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
package org.opensearch.security.resources;

import org.opensearch.Version;

/**
 * This class contains constants related to resource sharing in OpenSearch.
 *
 * @opensearch.experimental
 */
public class ResourceSharingConstants {
    // Resource sharing index
    public static final String OPENSEARCH_RESOURCE_SHARING_INDEX = ".opensearch_resource_sharing";

    // Resource sharing feature minimum supported version
    public static final Version RESOURCE_SHARING_MIN_SUPPORTED_VERSION = Version.V_3_0_0;
}
