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

package org.opensearch.security.tools.democonfig.util;

/**
 * Helper class to allow capturing and testing exit codes and block test execution from exiting mid-way
 */
public class NoExitSecurityManager extends SecurityManager {
    @Override
    public void checkPermission(java.security.Permission perm) {
        // Allow everything except System.exit code 0 & -1
        if (perm instanceof java.lang.RuntimePermission && ("exitVM.0".equals(perm.getName()) || "exitVM.-1".equals(perm.getName()))) {
            StringBuilder sb = new StringBuilder();
            sb.append("System.exit(");
            sb.append(perm.getName().contains("0") ? 0 : -1);
            sb.append(") blocked to allow print statement testing.");
            throw new SecurityException(sb.toString());
        }
    }
}
