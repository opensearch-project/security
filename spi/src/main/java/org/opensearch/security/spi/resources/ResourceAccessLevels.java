/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

/**
 * This class represents action-groups to be utilized to share resources.
 *
 * @opensearch.experimental
 */
public interface ResourceAccessLevels {
    // TODO update following comment once ResourceAuthz is implemented as a standalone framework
    // At present, we define this place-holder value represents the default action group this resource is shared with.
    String PLACE_HOLDER = "default";
}
