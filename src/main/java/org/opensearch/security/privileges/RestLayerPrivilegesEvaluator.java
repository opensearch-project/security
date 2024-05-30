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

package org.opensearch.security.privileges;

import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.security.user.User;

public class RestLayerPrivilegesEvaluator {
    protected final Logger log = LogManager.getLogger(this.getClass());
    private final PrivilegesEvaluator privilegesEvaluator;

    public RestLayerPrivilegesEvaluator(PrivilegesEvaluator privilegesEvaluator) {
        this.privilegesEvaluator = privilegesEvaluator;
    }

    public PrivilegesEvaluatorResponse evaluate(final User user, final String routeName, final Set<String> actions) {
        PrivilegesEvaluationContext context = privilegesEvaluator.createContext(user, routeName);

        final boolean isDebugEnabled = log.isDebugEnabled();
        if (isDebugEnabled) {
            log.debug("Evaluate permissions for {}", user);
            log.debug("Action: {}", actions);
            log.debug("Mapped roles: {}", context.getMappedRoles().toString());
        }

        PrivilegesEvaluatorResponse result = privilegesEvaluator.getActionPrivileges().hasAnyClusterPrivilege(context, actions);

        if (!result.allowed) {
            log.info(
                "No permission match for {} [Action [{}]] [RolesChecked {}]. No permissions for {}",
                user,
                routeName,
                context.getMappedRoles(),
                result.getMissingPrivileges()
            );
        }

        return result;
    }
}
