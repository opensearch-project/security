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

import java.util.Collections;
import java.util.List;

import com.google.common.collect.ImmutableList;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.support.Utils.addDeprecatedRoutesPrefix;

/**
 * This class implements GET and PUT operations to manage dynamic WhitelistingSettings.
 * <p>
 * These APIs are only accessible to SuperAdmin since the configuration controls what APIs are accessible by normal users.
 * Eg: If whitelisting is enabled, and a specific API like "/_cat/nodes" is not whitelisted, then only the SuperAdmin can use "/_cat/nodes"
 * These APIs allow the SuperAdmin to enable/disable whitelisting, and also change the list of whitelisted APIs.
 * <p>
 * A SuperAdmin is identified by a certificate which represents a distinguished name(DN).
 * SuperAdmin DN's can be set in {@link ConfigConstants#SECURITY_AUTHCZ_ADMIN_DN}
 * SuperAdmin certificate for the default superuser is stored as a kirk.pem file in config folder of OpenSearch
 * <p>
 * Example calling the PUT API as SuperAdmin using curl (if http basic auth is on):
 * curl -v --cacert path_to_config/root-ca.pem --cert path_to_config/kirk.pem --key path_to_config/kirk-key.pem -XPUT https://localhost:9200/_opendistro/_security/api/whitelist -H "Content-Type: application/json" -d’
 * {
 *      "enabled" : false,
 *      "requests" : {"/_cat/nodes": ["GET"], "/_opendistro/_security/api/whitelist": ["GET"]}
 * }
 *
 * Example using the PATCH API to change the requests as SuperAdmin:
 * curl -v --cacert path_to_config/root-ca.pem --cert path_to_config/kirk.pem --key path_to_config/kirk-key.pem -XPATCH https://localhost:9200/_opendistro/_security/api/whitelist -H "Content-Type: application/json" -d’
 * {
 *      "op":"replace",
 *      "path":"/config/requests",
 *      "value": {"/_cat/nodes": ["GET"], "/_opendistro/_security/api/whitelist": ["GET"]}
 * }
 *
 * To update enabled, use the "add" operation instead of the "replace" operation, since boolean variables are not recognized as valid paths when they are false.
 * eg:
 * curl -v --cacert path_to_config/root-ca.pem --cert path_to_config/kirk.pem --key path_to_config/kirk-key.pem -XPATCH https://localhost:9200/_opendistro/_security/api/whitelist -H "Content-Type: application/json" -d’
 * {
 *      "op":"add",
 *      "path":"/config/enabled",
 *      "value": true
 * }
 *
 * The backing data is stored in {@link ConfigConstants#SECURITY_CONFIG_INDEX_NAME} which is populated during bootstrap.
 * For existing clusters, {@link SecurityAdmin} tool can
 * be used to populate the index.
 * <p>
 */
public class WhitelistApiAction extends AllowlistApiAction {
    private static final List<DeprecatedRoute> routes = addDeprecatedRoutesPrefix(
        ImmutableList.of(
            new DeprecatedRoute(
                RestRequest.Method.GET,
                "/whitelist",
                "[/whitelist] is a deprecated endpoint. Please use [/allowlist] instead."
            ),
            new DeprecatedRoute(
                RestRequest.Method.PUT,
                "/whitelist",
                "[/whitelist] is a deprecated endpoint. Please use [/allowlist] instead."
            ),
            new DeprecatedRoute(
                RestRequest.Method.PATCH,
                "/whitelist",
                "[/whitelist] is a deprecated endpoint. Please use [/allowlist] instead."
            )
        )
    );

    @Inject
    public WhitelistApiAction(
        final ClusterService clusterService,
        final ThreadPool threadPool,
        final SecurityApiDependencies securityApiDependencies
    ) {
        super(Endpoint.WHITELIST, clusterService, threadPool, securityApiDependencies);
    }

    public List<Route> routes() {
        return Collections.emptyList();
    }

    @Override
    public List<DeprecatedRoute> deprecatedRoutes() {
        return routes;
    }

    @Override
    protected CType getConfigType() {
        return CType.WHITELIST;
    }

}
