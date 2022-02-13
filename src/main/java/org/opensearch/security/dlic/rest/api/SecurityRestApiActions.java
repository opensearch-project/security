/*
 * Copyright OpenSearch Contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
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
        handlers.add(new AuditApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        return Collections.unmodifiableCollection(handlers);
    }

}
