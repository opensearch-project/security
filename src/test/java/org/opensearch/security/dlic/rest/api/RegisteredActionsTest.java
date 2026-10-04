/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.dlic.rest.api;

import java.util.Set;

import org.junit.Test;

import org.opensearch.action.ActionModule.DynamicActionRegistry;
import org.opensearch.extensions.rest.RestSendToExtensionAction;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest.Method;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

public class RegisteredActionsTest {
    @Test
    public void readsCurrentRegistryInsteadOfCachingNames() {
        var registry = new DynamicActionRegistry();
        var actions = new RegisteredActions();
        actions.initialize(registry);
        assertTrue(actions.names().isEmpty());
        var route = new NamedRoute.Builder().method(Method.GET).path("/example").uniqueName("example").build();
        registry.registerDynamicRoute(route, mock(RestSendToExtensionAction.class));
        assertEquals(Set.of("example"), actions.names());
        registry.unregisterDynamicRoute(route);
        assertTrue(actions.names().isEmpty());
    }
}
