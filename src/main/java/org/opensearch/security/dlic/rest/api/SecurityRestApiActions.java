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
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.configuration.SecurityConfigVersionHandler;
import org.opensearch.security.configuration.SecurityConfigVersionsLoader;
import org.opensearch.security.hasher.PasswordHasher;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.resources.ResourcePluginInfo;
import org.opensearch.security.resources.ResourceSharingIndexHandler;
import org.opensearch.security.resources.migrate.MigrateResourceSharingInfoApiAction;
import org.opensearch.security.ssl.SslSettingsManager;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.user.UserService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

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
        final SslSettingsManager sslSettingsManager,
        final UserService userService,
        final boolean certificatesReloadEnabled,
        final PasswordHasher passwordHasher,
        final ResourceSharingIndexHandler resourceSharingIndexHandler,
        final ResourcePluginInfo resourcePluginInfo
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
        List<RestHandler> handler = new ArrayList<>(
            List.of(
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
                new AccountApiAction(clusterService, threadPool, securityApiDependencies, passwordHasher),
                new NodesDnApiAction(clusterService, threadPool, securityApiDependencies),
                new AllowlistApiAction(Endpoint.ALLOWLIST, clusterService, threadPool, securityApiDependencies),
                new AuditApiAction(clusterService, threadPool, securityApiDependencies),
                new MultiTenancyConfigApiAction(clusterService, threadPool, securityApiDependencies),
                new RateLimitersApiAction(clusterService, threadPool, securityApiDependencies),
                new ConfigUpgradeApiAction(clusterService, threadPool, securityApiDependencies),
                new SecuritySSLCertsApiAction(
                    clusterService,
                    threadPool,
                    sslSettingsManager,
                    certificatesReloadEnabled,
                    securityApiDependencies
                ),
                new CertificatesApiAction(clusterService, threadPool, securityApiDependencies),
                new MigrateResourceSharingInfoApiAction(
                    clusterService,
                    threadPool,
                    securityApiDependencies,
                    resourceSharingIndexHandler,
                    resourcePluginInfo
                )
            )
        );

        if (SecurityConfigVersionHandler.isVersionIndexEnabled(settings)) {
            handler.add(
                new ViewVersionApiAction(
                    clusterService,
                    threadPool,
                    securityApiDependencies,
                    new SecurityConfigVersionsLoader(client, settings)
                )
            );
            handler.add(
                new RollbackVersionApiAction(
                    clusterService,
                    threadPool,
                    securityApiDependencies,
                    new SecurityConfigVersionsLoader(client, settings),
                    configurationRepository,
                    client
                )
            );
        }

        return handler;
    }

}
