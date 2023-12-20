/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.bwc;

public enum ClusterType {
    OLD,
    MIXED,
    UPGRADED;

    public static ClusterType parse(String value) {
        switch (value) {
            case "old_cluster":
                return OLD;
            case "mixed_cluster":
                return MIXED;
            case "upgraded_cluster":
                return UPGRADED;
            default:
                throw new AssertionError("unknown cluster type: " + value);
        }
    }
}
