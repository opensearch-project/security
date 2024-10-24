/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security.plugin;

import org.opensearch.action.ActionType;

public class RunClusterHealthAction extends ActionType<RunClusterHealthResponse> {
    public static final RunClusterHealthAction INSTANCE = new RunClusterHealthAction();
    public static final String NAME = "mock:cluster/monitor/health";

    private RunClusterHealthAction() {
        super(NAME, RunClusterHealthResponse::new);
    }
}
