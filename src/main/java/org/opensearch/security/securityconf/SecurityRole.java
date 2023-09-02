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

package org.opensearch.security.securityconf;

import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;

import java.util.Collection;
import java.util.Set;

public interface SecurityRole {

    void addClusterPerms(Collection<String> permittedClusterActions);

    void addTenant(ConfigModelV6.Tenant tenant);

    void addIndexPattern(IndexPattern indexPattern);

    boolean impliesClusterPermission(String action);

    String getName();

    Set<String> getAllResolvedPermittedIndices(
        IndexResolverReplacer.Resolved resolved,
        User user,
        String[] actions,
        IndexNameExpressionResolver resolver,
        ClusterService cs
    );

    Set<String> getClusterPerms();

    Set<IndexPattern> getIpatterns();

    WildcardMatcher getClusterPermsMatchers();
}
