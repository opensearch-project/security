/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.dlic.rest.api;

import java.util.Set;

import org.opensearch.action.ActionModule.DynamicActionRegistry;
import org.opensearch.common.inject.Inject;

/** Provides current node-local action names after the core registry has been injected. */
public class RegisteredActions {
    private DynamicActionRegistry registry;

    @Inject
    public void initialize(DynamicActionRegistry registry) {
        this.registry = registry;
    }

    public Set<String> names() {
        return registry.getRegisteredActionNames();
    }
}
