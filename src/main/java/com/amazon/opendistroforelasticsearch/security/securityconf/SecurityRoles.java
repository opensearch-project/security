package com.amazon.opendistroforelasticsearch.security.securityconf;

import java.util.Map;
import java.util.Set;

import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.collect.Tuple;

import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer.Resolved;
import com.amazon.opendistroforelasticsearch.security.user.User;

public abstract class SecurityRoles {

    public abstract boolean impliesClusterPermissionPermission(String action0);

    public abstract Set<String> getRoleNames();

    public abstract Set<String> reduce(Resolved requestedResolved, User user, String[] strings, IndexNameExpressionResolver resolver,
            ClusterService clusterService);

    public abstract boolean impliesTypePermGlobal(Resolved requestedResolved, User user, String[] allIndexPermsRequiredA, IndexNameExpressionResolver resolver,
            ClusterService clusterService);

    public abstract boolean get(Resolved requestedResolved, User user, String[] allIndexPermsRequiredA, IndexNameExpressionResolver resolver,
            ClusterService clusterService);

    public abstract Map<WildcardMatcher, Set<String>> getMaskedFields(User user, IndexNameExpressionResolver resolver, ClusterService clusterService);

    public abstract Tuple<Map<WildcardMatcher, Set<String>>, Map<WildcardMatcher, Set<String>>> getDlsFls(User user, IndexNameExpressionResolver resolver,
                                                                                            ClusterService clusterService);

    public abstract Set<String> getAllPermittedIndicesForKibana(Resolved resolved, User user, String[] actions, IndexNameExpressionResolver resolver, ClusterService cs);

    public abstract SecurityRoles filter(Set<String> roles);

}
