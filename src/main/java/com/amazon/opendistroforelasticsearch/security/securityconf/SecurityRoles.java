package com.amazon.opendistroforelasticsearch.security.securityconf;

import java.util.Map;
import java.util.Set;

import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.collect.Tuple;

import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer.Resolved;
import com.amazon.opendistroforelasticsearch.security.user.User;

public interface SecurityRoles {

    boolean impliesClusterPermissionPermission(String action0);

    Set<String> getRoleNames();

    Set<String> reduce(Resolved requestedResolved, User user, String[] strings, IndexNameExpressionResolver resolver, ClusterService clusterService);

    boolean impliesTypePermGlobal(Resolved requestedResolved, User user, String[] allIndexPermsRequiredA, IndexNameExpressionResolver resolver, ClusterService clusterService);

    boolean get(Resolved requestedResolved, User user, String[] allIndexPermsRequiredA, IndexNameExpressionResolver resolver, ClusterService clusterService);

    Map<String, Set<String>> getMaskedFields(User user, IndexNameExpressionResolver resolver, ClusterService clusterService);

    Tuple<Map<String, Set<String>>, Map<String, Set<String>>> getDlsFls(User user, IndexNameExpressionResolver resolver, ClusterService clusterService);

    Set<String> getAllPermittedIndicesForKibana(Resolved resolved, User user, String[] actions, IndexNameExpressionResolver resolver, ClusterService cs);

    SecurityRoles filter(Set<String> roles);

}
