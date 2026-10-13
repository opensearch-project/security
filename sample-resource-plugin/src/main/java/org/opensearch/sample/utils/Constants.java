/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.utils;

/**
 * Constants for Sample Resource Sharing Plugin
 */
public class Constants {
    public static final String RESOURCE_INDEX_NAME = ".sample_resource";
    public static final String RESOURCE_TYPE = "sample-resource";
    public static final String RESOURCE_GROUP_TYPE = "sample-resource-group";
    // Must equal ResourceAccessHandler.WORKSPACE_RESOURCE_TYPE: the security plugin resolves workspace containers by
    // this exact type name. Registered so the write-path container fan-out can be exercised end-to-end.
    public static final String WORKSPACE_TYPE = "workspace";

    public static final String SAMPLE_RESOURCE_PLUGIN_PREFIX = "_plugins/sample_plugin";
    public static final String SAMPLE_RESOURCE_PLUGIN_API_PREFIX = "/" + SAMPLE_RESOURCE_PLUGIN_PREFIX;
}
