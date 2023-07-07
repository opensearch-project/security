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

package org.opensearch.security.privileges;

import java.util.Collections;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.securityconf.SecurityRoles;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class RestLayerPrivilegesEvaluatorTest {

    @Mock
    private ClusterService clusterService;
    @Mock
    private ThreadPool threadPool;
    @Mock
    private AtomicReference<NamedXContentRegistry> namedXContentRegistry;
    @Mock
    private ConfigModel configModel;
    @Mock
    private DynamicConfigModel dcm;
    @Mock
    private PrivilegesEvaluatorResponse presponse;
    @Mock
    private Logger log;

    private RestLayerPrivilegesEvaluator privilegesEvaluator;

    private static final User TEST_USER = new User("test_user");

    @Before
    public void setUp() throws InstantiationException, IllegalAccessException {
        MockitoAnnotations.openMocks(this);

        ThreadContext context = new ThreadContext(Settings.EMPTY);
        when(threadPool.getThreadContext()).thenReturn(context);

        privilegesEvaluator = new RestLayerPrivilegesEvaluator(
            clusterService,
            threadPool,
            mock(AuditLog.class),
            mock(ClusterInfoHolder.class),
            namedXContentRegistry
        );
        privilegesEvaluator.onConfigModelChanged(configModel);
        privilegesEvaluator.onDynamicConfigModelChanged(dcm);

        when(log.isDebugEnabled()).thenReturn(false);
    }

    @Test
    public void testEvaluate_Initialized_Success() {
        String action = "action";
        SecurityRoles securityRoles = mock(SecurityRoles.class);
        when(configModel.getSecurityRoles()).thenReturn(securityRoles);
        when(configModel.getSecurityRoles().filter(Collections.emptySet())).thenReturn(securityRoles);
        when(securityRoles.impliesClusterPermissionPermission(action)).thenReturn(false);

        PrivilegesEvaluatorResponse response = privilegesEvaluator.evaluate(TEST_USER, Set.of(action));

        assertNotNull(response);
        assertFalse(response.isAllowed());
        assertFalse(response.getMissingPrivileges().isEmpty());
        assertTrue(response.getResolvedSecurityRoles().isEmpty());
        verify(configModel, times(3)).getSecurityRoles();
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testEvaluate_NotInitialized_ExceptionThrown() throws Exception {
        String action = "action";
        privilegesEvaluator.evaluate(TEST_USER, Set.of(action));
    }

    @Test
    public void testMapRoles_ReturnsMappedRoles() {
        Set<String> mappedRoles = Collections.singleton("role1");
        when(configModel.mapSecurityRoles(any(), any())).thenReturn(mappedRoles);

        Set<String> result = privilegesEvaluator.mapRoles(any(), any());

        assertEquals(mappedRoles, result);
        verify(configModel).mapSecurityRoles(any(), any());
    }

    @Test
    public void testEvaluate_Successful_NewPermission() {
        String action = "hw:greet";
        SecurityRoles securityRoles = mock(SecurityRoles.class);
        when(configModel.getSecurityRoles()).thenReturn(securityRoles);
        when(configModel.getSecurityRoles().filter(Collections.emptySet())).thenReturn(securityRoles);
        when(securityRoles.impliesClusterPermissionPermission(action)).thenReturn(true);

        PrivilegesEvaluatorResponse response = privilegesEvaluator.evaluate(TEST_USER, Set.of(action));

        assertTrue(response.allowed);
        verify(securityRoles).impliesClusterPermissionPermission(any());
    }

    @Test
    public void testEvaluate_Successful_LegacyPermission() {
        String action = "cluster:admin/opensearch/hw/greet";
        SecurityRoles securityRoles = mock(SecurityRoles.class);
        when(configModel.getSecurityRoles()).thenReturn(securityRoles);
        when(configModel.getSecurityRoles().filter(Collections.emptySet())).thenReturn(securityRoles);
        when(securityRoles.impliesClusterPermissionPermission(action)).thenReturn(true);

        PrivilegesEvaluatorResponse response = privilegesEvaluator.evaluate(TEST_USER, Set.of(action));

        assertTrue(response.allowed);
        verify(securityRoles).impliesClusterPermissionPermission(any());
    }

    @Test
    public void testEvaluate_Unsuccessful() {
        String action = "action";
        SecurityRoles securityRoles = mock(SecurityRoles.class);
        when(configModel.getSecurityRoles()).thenReturn(securityRoles);
        when(configModel.getSecurityRoles().filter(Collections.emptySet())).thenReturn(securityRoles);
        when(securityRoles.impliesClusterPermissionPermission(action)).thenReturn(false);

        PrivilegesEvaluatorResponse response = privilegesEvaluator.evaluate(TEST_USER, Set.of(action));

        assertFalse(response.allowed);
        verify(securityRoles).impliesClusterPermissionPermission(any());
    }
}
