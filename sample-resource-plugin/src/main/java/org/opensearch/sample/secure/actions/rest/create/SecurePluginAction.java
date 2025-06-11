/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.secure.actions.rest.create;

import org.opensearch.action.ActionType;

/**
 * Action for testing running actions with PluginSubject
 */
public class SecurePluginAction extends ActionType<SecurePluginResponse> {
    /**
     * Secure plugin action instance
     */
    public static final SecurePluginAction INSTANCE = new SecurePluginAction();
    /**
     * Secure plugin action name
     */
    public static final String NAME = "cluster:admin/sample-resource-plugin/run-actions";

    private SecurePluginAction() {
        super(NAME, SecurePluginResponse::new);
    }
}
