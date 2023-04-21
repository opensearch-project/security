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
import java.util.Collections;
import java.util.List;

import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.ssl.SecurityKeyStore;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.user.UserService;
import org.opensearch.threadpool.ThreadPool;

public class SecurityRestApiActions {

    public static Collection<RestHandler> getHandler(final Settings settings,
                                                     final Path configPath,
                                                     final RestController controller,
                                                     final Client client,
                                                     final AdminDNs adminDns,
                                                     final ConfigurationRepository cr,
                                                     final ClusterService cs,
                                                     final PrincipalExtractor principalExtractor,
                                                     final PrivilegesEvaluator evaluator,
                                                     final ThreadPool threadPool,
                                                     final AuditLog auditLog,
                                                     final SecurityKeyStore securityKeyStore,
                                                     final UserService userService,
                                                     final boolean certificatesReloadEnabled) {
        final List<RestHandler> handlers = new ArrayList<RestHandler>(16);
        handlers.add(new InternalUsersApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, userService, auditLog));
        handlers.add(new RolesMappingApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new RolesApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new ActionGroupsApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new FlushCacheApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new SecurityConfigAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new PermissionsInfoAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new AuthTokenProcessorAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new TenantsApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new MigrateApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new ValidateApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new AccountApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new NodesDnApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new WhitelistApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new AllowlistApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new AuditApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new SecuritySSLCertsAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog, securityKeyStore, certificatesReloadEnabled));
        return Collections.unmodifiableCollection(handlers);
    }

}
