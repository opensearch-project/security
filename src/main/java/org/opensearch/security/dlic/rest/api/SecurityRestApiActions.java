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
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.threadpool.ThreadPool;

public class SecurityRestApiActions {

    public static Collection<RestHandler> getHandler(Settings settings, Path configPath, RestController controller, Client client,
                                                     AdminDNs adminDns, ConfigurationRepository cr, ClusterService cs, PrincipalExtractor principalExtractor,
                                                     final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
        final List<RestHandler> handlers = new ArrayList<RestHandler>(15);
        handlers.add(new InternalUsersApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
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
        return Collections.unmodifiableCollection(handlers);
    }

}
