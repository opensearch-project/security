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

import java.nio.file.Path;
import java.util.Collection;
import java.util.List;

import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.hasher.PasswordHasher;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.ssl.SecurityKeyStore;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.user.UserService;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;

public class SecurityRestApiActions {

    public static Collection<RestHandler> getHandler(
        final Settings settings,
        final Path configPath,
        final RestController controller,
        final Client client,
        final AdminDNs adminDns,
        final ConfigurationRepository configurationRepository,
        final ClusterService clusterService,
        final PrincipalExtractor principalExtractor,
        final PrivilegesEvaluator evaluator,
        final ThreadPool threadPool,
        final AuditLog auditLog,
        final UserService userService,
        final SecurityKeyStore securityKeyStore,
        final boolean certificatesReloadEnabled,
        final PasswordHasher passwordHasher
    ) {
        final var securityApiDependencies = new SecurityApiDependencies(
            adminDns,
            configurationRepository,
            evaluator,
            new RestApiPrivilegesEvaluator(settings, adminDns, evaluator, principalExtractor, configPath, threadPool),
            new RestApiAdminPrivilegesEvaluator(
                threadPool.getThreadContext(),
                evaluator,
                adminDns,
                settings.getAsBoolean(SECURITY_RESTAPI_ADMIN_ENABLED, false)
            ),
            auditLog,
            settings
        );
        return List.of(
            new InternalUsersApiAction(clusterService, threadPool, userService, securityApiDependencies, passwordHasher),
            new RolesMappingApiAction(clusterService, threadPool, securityApiDependencies),
            new RolesApiAction(clusterService, threadPool, securityApiDependencies),
            new ActionGroupsApiAction(clusterService, threadPool, securityApiDependencies),
            new FlushCacheApiAction(clusterService, threadPool, securityApiDependencies),
            new SecurityConfigApiAction(clusterService, threadPool, securityApiDependencies),
            // FIXME Change inheritance for PermissionsInfoAction
            new PermissionsInfoAction(
                settings,
                configPath,
                controller,
                client,
                adminDns,
                configurationRepository,
                clusterService,
                principalExtractor,
                evaluator,
                threadPool,
                auditLog
            ),
            new AuthTokenProcessorAction(clusterService, threadPool, securityApiDependencies),
            new TenantsApiAction(clusterService, threadPool, securityApiDependencies),
            new MigrateApiAction(clusterService, threadPool, securityApiDependencies),
            new ValidateApiAction(clusterService, threadPool, securityApiDependencies),
            new AccountApiAction(clusterService, threadPool, securityApiDependencies, passwordHasher),
            new NodesDnApiAction(clusterService, threadPool, securityApiDependencies),
            new WhitelistApiAction(clusterService, threadPool, securityApiDependencies),
            // FIXME change it as soon as WhitelistApiAction will be removed
            new AllowlistApiAction(Endpoint.ALLOWLIST, clusterService, threadPool, securityApiDependencies),
            new AuditApiAction(clusterService, threadPool, securityApiDependencies),
            new MultiTenancyConfigApiAction(clusterService, threadPool, securityApiDependencies),
            new ConfigUpgradeApiAction(clusterService, threadPool, securityApiDependencies),
            new SecuritySSLCertsApiAction(clusterService, threadPool, securityKeyStore, certificatesReloadEnabled, securityApiDependencies),
            new CertificatesApiAction(clusterService, threadPool, securityApiDependencies)
        );
    }

}
