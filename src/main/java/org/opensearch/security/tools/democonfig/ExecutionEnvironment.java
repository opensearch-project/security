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

package org.opensearch.security.tools.democonfig;

/**
 * The environment in which the demo config installation script is being executed
 */
public enum ExecutionEnvironment {
    DEMO, // default value
    TEST // to be used only for tests
}
