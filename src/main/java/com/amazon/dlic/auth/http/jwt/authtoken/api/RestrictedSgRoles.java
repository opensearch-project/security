package com.amazon.dlic.auth.http.jwt.authtoken.api;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer;
import com.amazon.opendistroforelasticsearch.security.securityconf.ConfigModel;
import com.amazon.opendistroforelasticsearch.security.securityconf.ConfigModelV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.SecurityRoles;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.collect.Tuple;

import com.google.common.collect.Sets;

public class RestrictedSgRoles implements SecurityRoles {

    private final SecurityRoles base;
    private final SecurityRoles restrictionSgRoles;
    private final RequestedPrivileges restriction;

    RestrictedSgRoles(SecurityRoles base, RequestedPrivileges restriction,
                      ConfigModel.ActionGroupResolver actionGroupResolver) {
        this.base = base;
        this.restriction = restriction;
        this.restrictionSgRoles = ConfigModelV7.SecurityRoles.create(restriction.toRolesConfig(), actionGroupResolver);
    }

    @Override
    public boolean impliesClusterPermissionPermission(String action0) {
        return base.impliesClusterPermissionPermission(action0) && restrictionSgRoles.impliesClusterPermissionPermission(action0);
    }

    @Override
    public Set<String> getRoleNames() {
        if (restriction.getRoles() == null || restriction.getRoles().size() == 0) {
            return base.getRoleNames();
        }

        Set<String> result = new HashSet<>(restriction.getRoles().size());
        Set<String> baseRoles = base.getRoleNames();

        for (String role : restriction.getRoles()) {
            if (baseRoles.contains(role)) {
                result.add(role);
            }
        }

        return result;
    }

    @Override
    public Set<String> reduce(IndexResolverReplacer.Resolved requestedResolved, User user, String[] strings, IndexNameExpressionResolver resolver,
                              ClusterService clusterService) {
        Set<String> restrictedIndexes = restrictionSgRoles.reduce(requestedResolved, user, strings, resolver, clusterService);

        if (restrictedIndexes.isEmpty()) {
            // Don't calculate base indexes if we already know we will get an empty set
            return Collections.emptySet();
        }

        Set<String> baseIndexes = base.reduce(requestedResolved, user, strings, resolver, clusterService);

        return Sets.intersection(baseIndexes, restrictedIndexes);
    }

    @Override
    public boolean impliesTypePermGlobal(IndexResolverReplacer.Resolved requestedResolved, User user, String[] allIndexPermsRequiredA, IndexNameExpressionResolver resolver,
                                         ClusterService clusterService) {
        boolean restrictedPermission = restrictionSgRoles.impliesTypePermGlobal(requestedResolved, user, allIndexPermsRequiredA, resolver,
                clusterService);

        if (!restrictedPermission) {
            // Don't calculate base permission if we already know we will get an empty set
            return false;
        }

        boolean basePermission = base.impliesTypePermGlobal(requestedResolved, user, allIndexPermsRequiredA, resolver, clusterService);

        return restrictedPermission && basePermission;
    }

    @Override
    public boolean get(IndexResolverReplacer.Resolved requestedResolved, User user, String[] allIndexPermsRequiredA, IndexNameExpressionResolver resolver,
                       ClusterService clusterService) {
        boolean restrictedPermission = restrictionSgRoles.get(requestedResolved, user, allIndexPermsRequiredA, resolver, clusterService);

        if (!restrictedPermission) {
            // Don't calculate base permission if we already know we will get an empty set
            return false;
        }

        boolean basePermission = base.get(requestedResolved, user, allIndexPermsRequiredA, resolver, clusterService);

        return restrictedPermission && basePermission;
    }

    @Override
    public Map<String, Set<String>> getMaskedFields(User user, IndexNameExpressionResolver resolver, ClusterService clusterService) {
        // TODO not yet implemented
        return base.getMaskedFields(user, resolver, clusterService);
    }

    @Override
    public Tuple<Map<String, Set<String>>, Map<String, Set<String>>> getDlsFls(User user, IndexNameExpressionResolver resolver,
                                                                               ClusterService clusterService) {
        // TODO not yet implemented
        return base.getDlsFls(user, resolver, clusterService);
    }

    @Override
    public Set<String> getAllPermittedIndicesForKibana(IndexResolverReplacer.Resolved resolved, User user, String[] actions, IndexNameExpressionResolver resolver,
                                                       ClusterService cs) {
        Set<String> restrictedIndexes = restrictionSgRoles.getAllPermittedIndicesForKibana(resolved, user, actions, resolver, cs);

        if (restrictedIndexes.isEmpty()) {
            // Don't calculate base indexes if we already know we will get an empty set
            return Collections.emptySet();
        }

        Set<String> baseIndexes = base.getAllPermittedIndicesForKibana(resolved, user, actions, resolver, cs);

        return Sets.intersection(baseIndexes, restrictedIndexes);
    }

    @Override
    public SecurityRoles filter(Set<String> roles) {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public TenantPermissions getTenantPermissions(User user, String requestedTenant) {
        TenantPermissions restricted = restrictionSgRoles.getTenantPermissions(user, requestedTenant);
        TenantPermissions base = this.base.getTenantPermissions(user, requestedTenant);

        return new TenantPermissions() {

            @Override
            public boolean isWritePermitted() {
                return restricted.isWritePermitted() && base.isWritePermitted();
            }

            @Override
            public boolean isReadPermitted() {
                return restricted.isReadPermitted() && base.isReadPermitted();
            }

            @Override
            public Set<String> getPermissions() {
                return Sets.intersection(restricted.getPermissions(), base.getPermissions());
            }
        };
    }

    @Override
    public boolean hasTenantPermission(User user, String requestedTenant, String action) {
        boolean restrictedPermission = restrictionSgRoles.hasTenantPermission(user, requestedTenant, action);

        if (!restrictedPermission) {
            return false;
        }

        boolean basePermission = base.hasTenantPermission(user, requestedTenant, action);

        return restrictedPermission && basePermission;
    }

    @Override
    public Map<String, Boolean> mapTenants(User user, Set<String> tenantNames) {
        Map<String, Boolean> restricted = restrictionSgRoles.mapTenants(user, tenantNames);
        Map<String, Boolean> base = this.base.mapTenants(user, tenantNames);

        HashMap<String, Boolean> result = new HashMap<>(base.size());

        for (Map.Entry<String, Boolean> entry : base.entrySet()) {
            Boolean restrictedBoolean = restricted.get(entry.getKey());

            if (restrictedBoolean != null) {
                result.put(entry.getKey(), restrictedBoolean.booleanValue() && entry.getValue());
            }
        }

        return result;
    }

}

