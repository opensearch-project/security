/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.dlic.rest.validation;

import java.util.Map;
import java.util.Set;

import org.junit.Test;

import org.opensearch.action.ActionModule.DynamicActionRegistry;
import org.opensearch.action.search.SearchAction;
import org.opensearch.action.support.TransportAction;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.transport.RequestHandlerRegistry;
import org.opensearch.transport.TransportService;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

public class RolePermissionValidatorTest {
    private final DynamicActionRegistry registry = new DynamicActionRegistry();
    private final TransportService transportService = mock(TransportService.class);
    private final RolePermissionValidator validator = new RolePermissionValidator();

    public RolePermissionValidatorTest() {
        validator.initialize(registry, transportService);
    }

    private boolean valid(String permission, Set<String> groups) {
        var mapper = DefaultObjectMapper.objectMapper();
        var role = mapper.createObjectNode();
        role.putArray("cluster_permissions").add(permission);
        role.putArray("index_permissions").addObject().putArray("allowed_actions").add(permission);
        return validator.validate(role, groups).isValid();
    }

    @Test
    public void acceptsRegisteredActionsInEitherPermissionList() {
        registry.registerUnmodifiableActionMap(Map.of(SearchAction.INSTANCE, mock(TransportAction.class)));
        assertTrue(valid(SearchAction.NAME, Set.of()));
        assertFalse(valid("indices:data/read/searhc", Set.of()));
    }

    @Test
    public void observesDynamicRegistrationAndRemoval() {
        assertFalse(valid(SearchAction.NAME, Set.of()));
        registry.registerDynamicAction(SearchAction.INSTANCE, mock(TransportAction.class));
        assertTrue(valid(SearchAction.NAME, Set.of()));
        registry.unregisterDynamicAction(SearchAction.INSTANCE);
        assertFalse(valid(SearchAction.NAME, Set.of()));
    }

    @Test
    public void acceptsTransportSubActions() {
        var handler = new RequestHandlerRegistry<>("indices:data/write/bulk[s]", null, null, null, "same", false, false);
        doReturn(handler).when(transportService).getRequestHandler("indices:data/write/bulk[s]");
        assertTrue(valid("indices:data/write/bulk[s]", Set.of()));
        assertFalse(valid("indices:data/write/bulk[typo]", Set.of()));
    }

    @Test
    public void acceptsNamedActionGroups() {
        assertTrue(valid("custom_group", Set.of("custom_group")));
        assertFalse(valid("custom_group_typo", Set.of("custom_group")));
    }

    @Test
    public void preservesPatterns() {
        assertTrue(valid("indices:data/read/*", Set.of()));
        assertTrue(valid("*", Set.of()));
        assertTrue(valid("/indices:.*/", Set.of()));
        assertFalse(valid("/[/", Set.of()));
    }

    @Test
    public void acceptsSecurityPermissionsButNotMisspellings() {
        assertTrue(valid("restapi:admin/roles", Set.of()));
        assertTrue(valid("restapi:admin/ssl/certs/info", Set.of()));
        assertTrue(valid("system:admin/system_index", Set.of()));
        assertFalse(valid("restapi:admin/rolez", Set.of()));
        assertFalse(valid("", Set.of()));
    }
}
