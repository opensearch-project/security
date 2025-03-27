package org.opensearch.security.configuration;

import org.opensearch.action.ActionRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;

public interface SettingsPermissionValve {
    boolean invoke(PrivilegesEvaluationContext context, ActionListener<?> listener);

    class NoopSettingsPermissionValve implements SettingsPermissionValve {
        @Override
        public boolean invoke(PrivilegesEvaluationContext context, ActionListener<?> listener) {
            return true;
        }
    }
}