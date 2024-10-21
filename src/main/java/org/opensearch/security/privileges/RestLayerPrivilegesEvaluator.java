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

import org.opensearch.security.user.User;

public interface RestLayerPrivilegesEvaluator {
    PrivilegesEvaluatorResponse evaluate(final User user, final String routeName, final Set<String> actions);
}
