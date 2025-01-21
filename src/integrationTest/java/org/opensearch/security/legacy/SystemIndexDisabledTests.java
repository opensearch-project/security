package org.opensearch.security.legacy;

import java.util.List;
import java.util.Map;

import org.junit.ClassRule;

import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.systemindex.AbstractSystemIndexDisabledTests;
import org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin1;
import org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin2;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

public class SystemIndexDisabledTests extends AbstractSystemIndexDisabledTests {
    public static final TestSecurityConfig.AuthcDomain AUTHC_DOMAIN = new TestSecurityConfig.AuthcDomain("basic", 0)
        .httpAuthenticatorWithChallenge("basic")
        .backend("internal");

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_DOMAIN)
        .users(USER_ADMIN)
        .plugin(SystemIndexPlugin1.class, SystemIndexPlugin2.class)
        .nodeSettings(
            Map.of(
                SECURITY_RESTAPI_ROLES_ENABLED,
                List.of("user_" + USER_ADMIN.getName() + "__" + ALL_ACCESS.getName()),
                SECURITY_SYSTEM_INDICES_ENABLED_KEY,
                false,
                PrivilegesEvaluator.USE_LEGACY_PRIVILEGE_EVALUATOR.getKey(),
                true
            )
        )
        .build();

    public SystemIndexDisabledTests() {
        super(cluster);
    }
}
