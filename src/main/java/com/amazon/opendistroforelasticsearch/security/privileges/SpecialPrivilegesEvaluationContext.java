package com.amazon.opendistroforelasticsearch.security.privileges;

import java.util.Set;

import com.amazon.opendistroforelasticsearch.security.securityconf.SecurityRoles;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.elasticsearch.common.transport.TransportAddress;


public interface SpecialPrivilegesEvaluationContext {
    User getUser();

    Set<String> getMappedRoles();

    SecurityRoles getOpendistroSecurityRoles();

    default TransportAddress getCaller() {
        return null;
    }

    default boolean requiresPrivilegeEvaluationForLocalRequests() {
        return false;
    }

    default boolean isSgConfigRestApiAllowed() {
        return false;
    }
}
