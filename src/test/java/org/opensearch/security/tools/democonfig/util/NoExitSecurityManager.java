package org.opensearch.security.tools.democonfig.util;

public class NoExitSecurityManager extends SecurityManager {
    @Override
    public void checkPermission(java.security.Permission perm) {
        // Allow everything except System.exit code 0 &b -1
        if (perm instanceof java.lang.RuntimePermission && ("exitVM.0".equals(perm.getName()) || "exitVM.-1".equals(perm.getName()))) {
            StringBuilder sb = new StringBuilder();
            sb.append("System.exit(");
            sb.append(perm.getName().contains("0") ? 0 : -1);
            sb.append(") blocked to allow print statement testing.");
            throw new SecurityException(sb.toString());
        }
    }
}
