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

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.securityconf.SecurityRoles;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.quality.Strictness;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

@RunWith(MockitoJUnitRunner.class)
public class RestLayerPrivilegesEvaluatorTest {

    @Mock(strictness = Mock.Strictness.LENIENT)
    private ClusterService clusterService;
    @Mock
    private ThreadPool threadPool;
    @Mock
    private ConfigModel configModel;

    private RestLayerPrivilegesEvaluator privilegesEvaluator;

    private static final User TEST_USER = new User("test_user");

    private void setLoggingLevel(final Level level) {
        final Logger restLayerPrivilegesEvaluatorLogger = LogManager.getLogger(RestLayerPrivilegesEvaluator.class);
        Configurator.setLevel(restLayerPrivilegesEvaluatorLogger, level);
    }

    @Before
    public void setUp() {
        when(threadPool.getThreadContext()).thenReturn(new ThreadContext(Settings.EMPTY));

        when(clusterService.localNode()).thenReturn(mock(DiscoveryNode.class, withSettings().strictness(Strictness.LENIENT)));
        privilegesEvaluator = new RestLayerPrivilegesEvaluator(
            clusterService,
            threadPool
        );
        privilegesEvaluator.onConfigModelChanged(configModel); // Defaults to the mocked config model
        verify(threadPool).getThreadContext(); // Called during construction of RestLayerPrivilegesEvaluator
        setLoggingLevel(Level.DEBUG); // Enable debug logging scenarios for verification
    }

    @After
    public void after() {
        setLoggingLevel(Level.INFO);
    }

    @Test
    public void testEvaluate_Initialized_Success() {
        String action = "action";
        SecurityRoles securityRoles = mock(SecurityRoles.class);
        when(configModel.getSecurityRoles()).thenReturn(securityRoles);
        when(configModel.getSecurityRoles().filter(Collections.emptySet())).thenReturn(securityRoles);
        when(securityRoles.impliesClusterPermissionPermission(action)).thenReturn(false);

        PrivilegesEvaluatorResponse response = privilegesEvaluator.evaluate(TEST_USER, Set.of(action));

        assertThat(response.isAllowed(), equalTo(false));
        assertThat(response.getMissingPrivileges(), equalTo(Set.of(action)));
        assertThat(response.getResolvedSecurityRoles(), Matchers.empty());
        verify(configModel, times(3)).getSecurityRoles();
    }

    @Test
    public void testEvaluate_NotInitialized_NullModel_ExceptionThrown() {
        // Null out the config model
        privilegesEvaluator.onConfigModelChanged(null);
        final OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> privilegesEvaluator.evaluate(TEST_USER, null)
        );
        assertThat(exception.getMessage(), equalTo("OpenSearch Security is not initialized."));
        verify(configModel, never()).getSecurityRoles();
    }

    @Test
    public void testEvaluate_NotInitialized_NoSecurityRoles_ExceptionThrown() {
        final OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> privilegesEvaluator.evaluate(TEST_USER, null)
        );
        assertThat(exception.getMessage(), equalTo("OpenSearch Security is not initialized."));
        verify(configModel).getSecurityRoles();
    }

    @Test
    public void testMapRoles_ReturnsMappedRoles() {
        final User user = mock(User.class);
        final Set<String> mappedRoles = Collections.singleton("role1");
        when(configModel.mapSecurityRoles(any(), any())).thenReturn(mappedRoles);

        final Set<String> result = privilegesEvaluator.mapRoles(user, null);

        assertThat(result, equalTo(mappedRoles));
        verifyNoInteractions(user);
        verify(configModel).mapSecurityRoles(user, null);
    }

    @Test
    public void testEvaluate_Successful_NewPermission() {
        String action = "hw:greet";
        SecurityRoles securityRoles = mock(SecurityRoles.class);
        when(configModel.getSecurityRoles()).thenReturn(securityRoles);
        when(configModel.getSecurityRoles().filter(Collections.emptySet())).thenReturn(securityRoles);
        when(securityRoles.impliesClusterPermissionPermission(action)).thenReturn(true);

        PrivilegesEvaluatorResponse response = privilegesEvaluator.evaluate(TEST_USER, Set.of(action));

        assertThat(response.allowed, equalTo(true));
        verify(securityRoles).impliesClusterPermissionPermission(action);
    }

    @Test
    public void testEvaluate_Successful_LegacyPermission() {
        String action = "cluster:admin/opensearch/hw/greet";
        SecurityRoles securityRoles = mock(SecurityRoles.class);
        when(configModel.getSecurityRoles()).thenReturn(securityRoles);
        when(configModel.getSecurityRoles().filter(Collections.emptySet())).thenReturn(securityRoles);
        when(securityRoles.impliesClusterPermissionPermission(action)).thenReturn(true);

        PrivilegesEvaluatorResponse response = privilegesEvaluator.evaluate(TEST_USER, Set.of(action));

        assertThat(response.allowed, equalTo(true));
        verify(securityRoles).impliesClusterPermissionPermission(action);
        verify(configModel, times(3)).getSecurityRoles();
    }

    @Test
    public void testEvaluate_Unsuccessful() {
        String action = "action";
        SecurityRoles securityRoles = mock(SecurityRoles.class);
        when(configModel.getSecurityRoles()).thenReturn(securityRoles);
        when(configModel.getSecurityRoles().filter(Collections.emptySet())).thenReturn(securityRoles);
        when(securityRoles.impliesClusterPermissionPermission(action)).thenReturn(false);

        PrivilegesEvaluatorResponse response = privilegesEvaluator.evaluate(TEST_USER, Set.of(action));

        assertThat(response.allowed, equalTo(false));
        verify(securityRoles).impliesClusterPermissionPermission(action);
    }
}
