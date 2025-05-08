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

package org.opensearch.security.configuration;

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