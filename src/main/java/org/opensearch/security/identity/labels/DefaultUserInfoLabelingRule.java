package org.opensearch.security.identity.labels;

import org.apache.commons.lang3.tuple.Pair;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.search.labels.rules.Rule;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.user.User;

import java.util.HashMap;
import java.util.Map;

/**
 * Rules to get user info labels for RuleBasedLabelingService in OpenSearch
 */
public class DefaultUserInfoLabelingRule implements Rule {
    public static final String REMOTE_ADDRESS = "remote_address";
    public static final String USER_NAME = "user_name";
    public static final String USER_SECURITY_ROLES = "user_backend_roles";
    public static final String USER_ROLES = "user_roles";
    public static final String USER_TENANT = "user_tenant";

    /**
     * @param threadContext
     * @param searchRequest
     * @return Map of User related info and the corresponding values
     */
    @Override
    public Map<String, String> evaluate(ThreadContext threadContext, SearchRequest searchRequest) {
        return getUserInfoFromThreadContext(threadContext);
    }

    /**
     * Get User info, specifically injected by the security plugin, from the thread context
     *
     * @param threadContext context of the thread
     * @return Map of User related info and the corresponding values
     */
    private Map<String, String> getUserInfoFromThreadContext(ThreadContext threadContext) {
        Map<String, String> userInfoMap = new HashMap<>();
        if (threadContext == null) {
            return userInfoMap;
        }
        final Pair<User, TransportAddress> userAndRemoteAddress = Utils.userAndRemoteAddressFrom(threadContext);
        TransportAddress remoteAddress = userAndRemoteAddress.getRight();
        if (remoteAddress != null) {
            userInfoMap.put(REMOTE_ADDRESS, remoteAddress.toString());
        }
        User user = userAndRemoteAddress.getLeft();
        if (user != null) {
            userInfoMap.put(USER_NAME, user.getName());
            userInfoMap.put(USER_ROLES, String.join(",", user.getRoles()));
            userInfoMap.put(USER_SECURITY_ROLES, String.join(",", user.getSecurityRoles()));
            userInfoMap.put(USER_TENANT, user.getRequestedTenant());
        }
        return userInfoMap;
    }
}
