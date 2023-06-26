package org.opensearch.security.securityconf;

import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.user.User;

import java.util.Set;

public interface SecurityRole {
    boolean impliesClusterPermission(String action);

    // get indices which are permitted for the given types and actions
    // dnfof + opensearchDashboards special only
    Set<String> getAllResolvedPermittedIndices(
        IndexResolverReplacer.Resolved resolved,
        User user,
        String[] actions,
        IndexNameExpressionResolver resolver,
        ClusterService cs
    );

    @Override
    String toString();

    Set<IndexPattern> getIpatterns();

    String getName();

}
