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

import java.util.Set;
import java.util.TreeMap;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.auditlog.NullAuditLog;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.user.User;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.quality.Strictness;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

@RunWith(MockitoJUnitRunner.class)
public class RestLayerPrivilegesEvaluatorTest {

    @Mock(strictness = Mock.Strictness.LENIENT)
    private ClusterService clusterService;
    @Mock
    private ConfigModel configModel;
    @Mock
    private DynamicConfigModel dynamicConfigModel;

    private static final User TEST_USER = new User("test_user");

    private void setLoggingLevel(final Level level) {
        final Logger restLayerPrivilegesEvaluatorLogger = LogManager.getLogger(RestLayerPrivilegesEvaluator.class);
        Configurator.setLevel(restLayerPrivilegesEvaluatorLogger, level);
    }

    @Before
    public void setUp() {
        when(clusterService.localNode()).thenReturn(mock(DiscoveryNode.class, withSettings().strictness(Strictness.LENIENT)));
        when(configModel.mapSecurityRoles(TEST_USER, null)).thenReturn(Set.of("test_role"));
        setLoggingLevel(Level.DEBUG); // Enable debug logging scenarios for verification
        ClusterState clusterState = mock(ClusterState.class);
        when(clusterService.state()).thenReturn(clusterState);
        Metadata metadata = mock(Metadata.class);
        when(clusterState.metadata()).thenReturn(metadata);
        when(metadata.getIndicesLookup()).thenReturn(new TreeMap<>());
    }

    @After
    public void after() {
        setLoggingLevel(Level.INFO);
    }

    @Test
    public void testEvaluate_Initialized_Success() throws Exception {
        String action = "action";
        SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("test_role:\n" + //
            "  cluster_permissions:\n" + //
            "  - any", CType.ROLES);

        PrivilegesEvaluator privilegesEvaluator = createPrivilegesEvaluator(roles);
        RestLayerPrivilegesEvaluator restPrivilegesEvaluator = new RestLayerPrivilegesEvaluator(privilegesEvaluator);

        PrivilegesEvaluatorResponse response = restPrivilegesEvaluator.evaluate(TEST_USER, "route_name", Set.of(action));

        assertThat(response.isAllowed(), equalTo(false));
        assertThat(response.getMissingPrivileges(), equalTo(Set.of(action)));
    }

    @Test
    public void testEvaluate_NotInitialized_NullModel_ExceptionThrown() {
        PrivilegesEvaluator privilegesEvaluator = createPrivilegesEvaluator(null);
        RestLayerPrivilegesEvaluator restPrivilegesEvaluator = new RestLayerPrivilegesEvaluator(privilegesEvaluator);
        final OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> restPrivilegesEvaluator.evaluate(TEST_USER, "route_name", null)
        );
        assertThat(exception.getMessage(), equalTo("OpenSearch Security is not initialized."));
    }

    @Test
    public void testEvaluate_Successful_NewPermission() throws Exception {
        String action = "hw:greet";
        SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("test_role:\n" + //
            "  cluster_permissions:\n" + //
            "  - hw:greet", CType.ROLES);
        PrivilegesEvaluator privilegesEvaluator = createPrivilegesEvaluator(roles);
        RestLayerPrivilegesEvaluator restPrivilegesEvaluator = new RestLayerPrivilegesEvaluator(privilegesEvaluator);
        PrivilegesEvaluatorResponse response = restPrivilegesEvaluator.evaluate(TEST_USER, "route_name", Set.of(action));
        assertThat(response.allowed, equalTo(true));
    }

    @Test
    public void testEvaluate_Successful_LegacyPermission() throws Exception {
        String action = "cluster:admin/opensearch/hw/greet";
        SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("test_role:\n" + //
            "  cluster_permissions:\n" + //
            "  - cluster:admin/opensearch/hw/greet", CType.ROLES);
        PrivilegesEvaluator privilegesEvaluator = createPrivilegesEvaluator(roles);
        RestLayerPrivilegesEvaluator restPrivilegesEvaluator = new RestLayerPrivilegesEvaluator(privilegesEvaluator);
        PrivilegesEvaluatorResponse response = restPrivilegesEvaluator.evaluate(TEST_USER, "route_name", Set.of(action));
        assertThat(response.allowed, equalTo(true));
    }

    @Test
    public void testEvaluate_Unsuccessful() throws Exception {
        String action = "action";
        SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("test_role:\n" + //
            "  cluster_permissions:\n" + //
            "  - other_action", CType.ROLES);
        PrivilegesEvaluator privilegesEvaluator = createPrivilegesEvaluator(roles);
        RestLayerPrivilegesEvaluator restPrivilegesEvaluator = new RestLayerPrivilegesEvaluator(privilegesEvaluator);
        PrivilegesEvaluatorResponse response = restPrivilegesEvaluator.evaluate(TEST_USER, "route_name", Set.of(action));
        assertThat(response.allowed, equalTo(false));
    }

    PrivilegesEvaluator createPrivilegesEvaluator(SecurityDynamicConfiguration<RoleV7> roles) {
        PrivilegesEvaluator privilegesEvaluator = new PrivilegesEvaluator(
            clusterService,
            () -> clusterService.state(),
            null,
            new ThreadContext(Settings.EMPTY),
            null,
            new IndexNameExpressionResolver(new ThreadContext(Settings.EMPTY)),
            new NullAuditLog(),
            Settings.EMPTY,
            null,
            null,
            null,
            null
        );
        privilegesEvaluator.onConfigModelChanged(configModel); // Defaults to the mocked config model
        privilegesEvaluator.onDynamicConfigModelChanged(dynamicConfigModel);

        if (roles != null) {
            privilegesEvaluator.updateConfiguration(SecurityDynamicConfiguration.empty(CType.ACTIONGROUPS), roles);
        }
        return privilegesEvaluator;
    }
}
