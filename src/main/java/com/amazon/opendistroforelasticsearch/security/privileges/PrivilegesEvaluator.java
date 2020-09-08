package com.amazon.opendistroforelasticsearch.security.privileges;

import com.amazon.opendistroforelasticsearch.security.user.User;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.tasks.Task;

import java.util.Map;
import java.util.Set;

public interface PrivilegesEvaluator {

    /**
     * evaluate() and isInitialized() are needed for any implementation of PrivilegesEvaluator interface
     */

    PrivilegesEvaluatorResponse evaluate(final User user, String action0, final ActionRequest request,
                                         Task task, final Set<String> injectedRoles);

    boolean isInitialized();

    /**
     * The below methods are called from outside PrivilegesEvaluator implementation, therefore kept in this interface
     */

    Set<String> mapRoles(User user, TransportAddress remoteAddress);

    Map<String, Boolean> mapTenants(User user, Set<String> securityRoles);

    boolean multitenancyEnabled();

    String kibanaIndex();

    String kibanaServerUsername();

    Set<String> getAllConfiguredTenantNames();

    boolean notFailOnForbiddenEnabled();

    String kibanaOpendistroRole();

}
