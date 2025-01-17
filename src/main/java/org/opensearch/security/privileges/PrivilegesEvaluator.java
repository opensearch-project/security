package org.opensearch.security.privileges;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.opensearch.action.ActionRequest;
import org.opensearch.common.settings.Setting;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.securityconf.impl.DashboardSignInOption;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;

public interface PrivilegesEvaluator {
    static Setting<Boolean> USE_LEGACY_PRIVILEGE_EVALUATOR = Setting.boolSetting(
        "plugins.security.privileges_evaluation.use_legacy_impl",
        false,
        Setting.Property.NodeScope
    );

    boolean hasRestAdminPermissions(final User user, final TransportAddress remoteAddress, final String permission);

    boolean isInitialized();

    PrivilegesEvaluationContext createContext(User user, String action);

    PrivilegesEvaluationContext createContext(User user, String action0, ActionRequest request, Task task, Set<String> injectedRoles);

    PrivilegesEvaluatorResponse evaluate(PrivilegesEvaluationContext context);

    Set<String> mapRoles(final User user, final TransportAddress caller);

    Map<String, Boolean> mapTenants(final User user, Set<String> roles);

    Set<String> getAllConfiguredTenantNames();

    boolean multitenancyEnabled();

    boolean privateTenantEnabled();

    String dashboardsDefaultTenant();

    boolean notFailOnForbiddenEnabled();

    String dashboardsIndex();

    String dashboardsServerUsername();

    String dashboardsOpenSearchRole();

    List<DashboardSignInOption> getSignInOptions();

    PrivilegesEvaluatorResponse hasExplicitIndexPrivilege(PrivilegesEvaluationContext context, Set<String> actions, String index);
}
