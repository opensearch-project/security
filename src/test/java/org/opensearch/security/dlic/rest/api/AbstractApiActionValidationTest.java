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

package org.opensearch.security.dlic.rest.api;

import java.io.IOException;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.configuration.ConfigurationMap;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.hasher.PasswordHasher;
import org.opensearch.security.hasher.PasswordHasherFactory;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public abstract class AbstractApiActionValidationTest {

    @Mock
    ClusterService clusterService;

    @Mock
    ThreadPool threadPool;

    @Mock
    ConfigurationRepository configurationRepository;

    @Mock
    RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator;

    SecurityApiDependencies securityApiDependencies;

    @Mock
    SecurityDynamicConfiguration<?> configuration;

    SecurityDynamicConfiguration<RoleV7> rolesConfiguration;

    ObjectMapper objectMapper = DefaultObjectMapper.objectMapper;

    PasswordHasher passwordHasher;

    @Before
    public void setup() {
        securityApiDependencies = new SecurityApiDependencies(
            null,
            configurationRepository,
            null,
            null,
            restApiAdminPrivilegesEvaluator,
            null,
            Settings.EMPTY
        );

        passwordHasher = PasswordHasherFactory.createPasswordHasher(
            Settings.builder().put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, ConfigConstants.BCRYPT).build()
        );
    }

    void setupRolesConfiguration() throws IOException {
        final var objectMapper = DefaultObjectMapper.objectMapper;
        final var config = objectMapper.createObjectNode();
        config.set("_meta", objectMapper.createObjectNode().put("type", CType.ROLES.toLCString()).put("config_version", 2));
        config.set("kibana_read_only", objectMapper.createObjectNode().put("reserved", true));
        config.set("some_hidden_role", objectMapper.createObjectNode().put("hidden", true));
        config.set("all_access", objectMapper.createObjectNode().put("static", true)); // it reserved as well
        config.set("security_rest_api_access", objectMapper.createObjectNode().put("reserved", true));

        final var array = objectMapper.createArrayNode();
        restApiAdminPermissions().forEach(array::add);
        config.set("rest_api_admin_role", objectMapper.createObjectNode().set("cluster_permissions", array));
        config.set("regular_role", objectMapper.createObjectNode().set("cluster_permissions", objectMapper.createArrayNode().add("*")));

        rolesConfiguration = SecurityDynamicConfiguration.fromJson(objectMapper.writeValueAsString(config), CType.ROLES, 2, 1, 1);
        when(configurationRepository.getConfigurationsFromIndex(List.of(CType.ROLES), false)).thenReturn(
            ConfigurationMap.of(rolesConfiguration)
        );
    }

    @Test
    public void allCrudActionsForDefaultValidatorAreForbidden() throws Exception {

        final var defaultPessimisticValidator = new AbstractApiAction(null, clusterService, threadPool, securityApiDependencies) {
            @Override
            protected CType<?> getConfigType() {
                return CType.CONFIG;
            }
        }.createEndpointValidator();

        var result = defaultPessimisticValidator.onConfigChange(SecurityConfiguration.of(null, configuration));
        assertThat(result.status(), is(RestStatus.FORBIDDEN));

        result = defaultPessimisticValidator.onConfigDelete(SecurityConfiguration.of(null, configuration));
        assertThat(result.status(), is(RestStatus.FORBIDDEN));

        result = defaultPessimisticValidator.onConfigLoad(SecurityConfiguration.of(null, configuration));
        assertThat(result.status(), is(RestStatus.FORBIDDEN));

    }

    protected JsonNode xContentToJsonNode(final ToXContent toXContent) {
        try (final var xContentBuilder = XContentFactory.jsonBuilder()) {
            toXContent.toXContent(xContentBuilder, ToXContent.EMPTY_PARAMS);
            return DefaultObjectMapper.readTree(xContentBuilder.toString());
        } catch (final IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    protected List<String> restApiAdminPermissions() {
        return List.of(
            "restapi:admin/actiongroups",
            "restapi:admin/allowlist",
            "restapi:admin/internalusers",
            "restapi:admin/nodesdn",
            "restapi:admin/roles",
            "restapi:admin/rolesmapping",
            "restapi:admin/ssl/certs/info",
            "restapi:admin/ssl/certs/reload",
            "restapi:admin/tenants",
            "restapi:admin/ratelimiters"
        );
    }

}
