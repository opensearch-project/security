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

import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.stream.Collectors;

import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.NullAuditLog;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.securityconf.ConfigModelV7;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.securityconf.DynamicConfigModelV7;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.user.User;
import org.opensearch.security.util.MockIndexMetadataBuilder;
import org.opensearch.test.framework.TestSecurityConfig;

import com.github.noconnor.junitperf.JUnitPerfRule;
import com.github.noconnor.junitperf.JUnitPerfTest;
import com.github.noconnor.junitperf.JUnitPerfTestRequirement;
import com.github.noconnor.junitperf.reporting.providers.ConsoleReportGenerator;
import com.github.noconnor.junitperf.reporting.providers.HtmlReportGenerator;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Ignore
public class PrivilegesEvaluatorPerformanceTest {

    final static String[] READ_PERMISSIONS = new String[] {
        "indices:data/read*",
        "indices:admin/mappings/fields/get*",
        "indices:admin/resolve/index" };

    final static TestSecurityConfig.User FULL_PRIVILEGES_TEST_USER = new TestSecurityConfig.User("full_privileges").roles(
        new TestSecurityConfig.Role("full_privileges_role").indexPermissions("*").on("*").clusterPermissions("*")
    );

    final static User FULL_PRIVILEGES_USER = user(FULL_PRIVILEGES_TEST_USER);

    final static TestSecurityConfig.User INDEX_A_READ_TEST_USER = new TestSecurityConfig.User("index_a_read").roles(
        new TestSecurityConfig.Role("index_a_read_role").indexPermissions(READ_PERMISSIONS)
            .on("index_a*")
            .clusterPermissions("cluster_composite_ops")
    );

    final static User INDEX_A_READ_USER = user(INDEX_A_READ_TEST_USER);

    final static TestSecurityConfig.User INDEX_A_READ_REGEX_TEST_USER = new TestSecurityConfig.User("index_a_read_regex").roles(
        new TestSecurityConfig.Role("index_a_read_regex_role").indexPermissions(READ_PERMISSIONS)
            .on("/^index_a.*/")
            .clusterPermissions("cluster_composite_ops")
    );

    final static User INDEX_A_READ_REGEX_USER = user(INDEX_A_READ_REGEX_TEST_USER);

    final static TestSecurityConfig.User INDEX_A_READ_ATTR_TEST_USER = new TestSecurityConfig.User("index_a_read_attr").attr("attr_a", "a")
        .roles(
            new TestSecurityConfig.Role("index_a_read_attr_role").indexPermissions(READ_PERMISSIONS)
                .on("index_${attr_internal_attr_a}*")
                .clusterPermissions("cluster_composite_ops")
        );

    final static User INDEX_A_READ_ATTR_USER = user(INDEX_A_READ_ATTR_TEST_USER);

    final static TestSecurityConfig.User INDEX_A_READ_ATTR_REGEX_TEST_USER = new TestSecurityConfig.User("index_a_read_attr").attr(
        "attr_a",
        "a"
    )
        .roles(
            new TestSecurityConfig.Role("index_a_read_attr_regex_role").indexPermissions(READ_PERMISSIONS)
                .on("/^index_${attr_internal_attr_a}.*/")
                .clusterPermissions("cluster_composite_ops")
        );

    final static User INDEX_A_READ_ATTR_REGEX_USER = user(INDEX_A_READ_ATTR_REGEX_TEST_USER);

    final static SearchRequest SEARCH_REQUEST = new SearchRequest("index_a*");

    final static TestSecurityConfig TEST_SECURITY_CONFIG = new TestSecurityConfig().users(
        FULL_PRIVILEGES_TEST_USER,
        INDEX_A_READ_TEST_USER,
        INDEX_A_READ_REGEX_TEST_USER,
        INDEX_A_READ_ATTR_TEST_USER,
        INDEX_A_READ_ATTR_REGEX_TEST_USER
    );

    final static TestSecurityConfig DNFOF_CONFIG = new TestSecurityConfig().doNotFailOnForbidden(true);

    @Rule
    public JUnitPerfRule perfTestRule = new JUnitPerfRule(new ConsoleReportGenerator(), new HtmlReportGenerator());

    final static PrivilegesEvaluator privilegesEvaluator10 = createPrivilegeEvaluator(10, false);

    final static PrivilegesEvaluator privilegesEvaluator100 = createPrivilegeEvaluator(100, false);

    final static PrivilegesEvaluator privilegesEvaluator1000 = createPrivilegeEvaluator(1000, false);

    final static PrivilegesEvaluator privilegesEvaluator10000 = createPrivilegeEvaluator(10000, false);

    final static PrivilegesEvaluator privilegesEvaluator10dnfof = createPrivilegeEvaluator(10, true);

    final static PrivilegesEvaluator privilegesEvaluator100dnfof = createPrivilegeEvaluator(100, true);

    final static PrivilegesEvaluator privilegesEvaluator1000dnfof = createPrivilegeEvaluator(1000, true);

    final static PrivilegesEvaluator privilegesEvaluator10000dnfof = createPrivilegeEvaluator(10000, true);

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_fullPrivileges_10indices() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator10.createContext(
            FULL_PRIVILEGES_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator10.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_fullPrivileges_100indices() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator100.createContext(
            FULL_PRIVILEGES_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator100.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_fullPrivileges_1000indices() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator1000.createContext(
            FULL_PRIVILEGES_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator1000.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_fullPrivileges_10000indices() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator10000.createContext(
            FULL_PRIVILEGES_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator10000.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivileges_10indices() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator10.createContext(
            INDEX_A_READ_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator10.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivileges_100indices() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator100.createContext(
            INDEX_A_READ_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator100.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivileges_1000indices() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator1000.createContext(
            INDEX_A_READ_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator1000.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivileges_10000indices() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator10000.createContext(
            INDEX_A_READ_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator10000.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithRegex_10indices() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator10.createContext(
            INDEX_A_READ_REGEX_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator10.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithRegex_100indices() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator100.createContext(
            INDEX_A_READ_REGEX_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator100.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithRegex_1000indices() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator1000.createContext(
            INDEX_A_READ_REGEX_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator1000.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithRegex_10000indices() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator10000.createContext(
            INDEX_A_READ_REGEX_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator10000.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithUserAttr_10indices() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator10.createContext(
            INDEX_A_READ_ATTR_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator10.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithUserAttr_100indices() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator100.createContext(
            INDEX_A_READ_ATTR_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator100.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithUserAttr_1000indices() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator1000.createContext(
            INDEX_A_READ_ATTR_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator1000.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithUserAttr_10000indices() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator10000.createContext(
            INDEX_A_READ_ATTR_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator10000.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithUserAttrAndRegex_10indices() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator10.createContext(
            INDEX_A_READ_ATTR_REGEX_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator10.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithUserAttrAndRegex_100indices() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator100.createContext(
            INDEX_A_READ_ATTR_REGEX_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator100.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithUserAttrAndRegex_1000indices() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator1000.createContext(
            INDEX_A_READ_ATTR_REGEX_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator1000.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithUserAttrAndRegex_10000indices() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator10000.createContext(
            INDEX_A_READ_ATTR_REGEX_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator10000.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_fullPrivileges_10indices_dnfof() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator10dnfof.createContext(
            FULL_PRIVILEGES_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator10dnfof.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_fullPrivileges_100indices_dnfof() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator100dnfof.createContext(
            FULL_PRIVILEGES_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator100dnfof.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_fullPrivileges_1000indices_dnfof() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator1000dnfof.createContext(
            FULL_PRIVILEGES_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator1000dnfof.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_fullPrivileges_10000indices_dnfof() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator10000dnfof.createContext(
            FULL_PRIVILEGES_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator10000dnfof.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivileges_10indices_dnfof() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator10dnfof.createContext(
            INDEX_A_READ_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator10dnfof.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivileges_100indices_dnfof() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator100dnfof.createContext(
            INDEX_A_READ_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator100dnfof.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivileges_1000indices_dnfof() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator1000dnfof.createContext(
            INDEX_A_READ_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator1000dnfof.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivileges_10000indices_dnfof() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator10000dnfof.createContext(
            INDEX_A_READ_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator10000dnfof.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithRegex_10indices_dnfof() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator10dnfof.createContext(
            INDEX_A_READ_REGEX_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator10dnfof.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithRegex_100indices_dnfof() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator100dnfof.createContext(
            INDEX_A_READ_REGEX_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator100dnfof.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithRegex_1000indices_dnfof() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator1000dnfof.createContext(
            INDEX_A_READ_REGEX_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator1000dnfof.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithRegex_10000indices_dnfof() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator10000dnfof.createContext(
            INDEX_A_READ_REGEX_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator10000dnfof.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithUserAttr_10indices_dnfof() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator10dnfof.createContext(
            INDEX_A_READ_ATTR_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator10dnfof.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithUserAttr_100indices_dnfof() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator100dnfof.createContext(
            INDEX_A_READ_ATTR_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator100dnfof.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithUserAttr_1000indices_dnfof() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator1000dnfof.createContext(
            INDEX_A_READ_ATTR_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator1000dnfof.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithUserAttr_10000indices_dnfof() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator10000dnfof.createContext(
            INDEX_A_READ_ATTR_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator10000dnfof.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithUserAttrAndRegex_10indices_dnfof() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator10dnfof.createContext(
            INDEX_A_READ_ATTR_REGEX_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator10dnfof.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithUserAttrAndRegex_100indices_dnfof() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator100dnfof.createContext(
            INDEX_A_READ_ATTR_REGEX_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator100dnfof.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithUserAttrAndRegex_1000indices_dnfof() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator1000dnfof.createContext(
            INDEX_A_READ_ATTR_REGEX_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator1000dnfof.evaluate(context);
        assertTrue(response.isAllowed());
    }

    @Test
    @JUnitPerfTest(threads = 50, durationMs = 125_000, warmUpMs = 10_000)
    @JUnitPerfTestRequirement(allowedErrorPercentage = 0.5f)
    public void evaluate_limitedPrivilegesWithUserAttrAndRegex_10000indices_dnfof() throws Exception {
        PrivilegesEvaluationContext context = privilegesEvaluator10000dnfof.createContext(
            INDEX_A_READ_ATTR_REGEX_USER,
            "indices:data/read/search",
            SEARCH_REQUEST,
            null,
            null
        );
        PrivilegesEvaluatorResponse response = privilegesEvaluator10000dnfof.evaluate(context);
        assertTrue(response.isAllowed());
    }

    static PrivilegesEvaluator createPrivilegeEvaluator(int numberOfIndices, boolean doNotFailOnForbidden) {
        SortedMap<String, IndexAbstraction> metaData = testIndices(numberOfIndices);
        ClusterService clusterService = mock(ClusterService.class, RETURNS_DEEP_STUBS);
        when(clusterService.state().metadata().getIndicesLookup()).thenReturn(metaData);

        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        ConfigurationRepository configurationRepository = mock(ConfigurationRepository.class);
        IndexNameExpressionResolver indexNameExpressionResolver = new IndexNameExpressionResolver(threadContext);
        AuditLog auditLog = new NullAuditLog();
        Settings settings = Settings.EMPTY;
        PrivilegesInterceptor privilegesInterceptor = new PrivilegesInterceptor(indexNameExpressionResolver, clusterService, null, null) {
            @Override
            public ReplaceResult replaceDashboardsIndex(
                final ActionRequest request,
                final String action,
                final User user,
                final DynamicConfigModel config,
                final IndexResolverReplacer.Resolved requestedResolved,
                final Map<String, Boolean> tenants
            ) {
                return PrivilegesInterceptor.CONTINUE_EVALUATION_REPLACE_RESULT;
            }
        };

        IndexResolverReplacer indexResolverReplacer = new IndexResolverReplacer(indexNameExpressionResolver, clusterService, null);
        NamedXContentRegistry namedXContentRegistry = NamedXContentRegistry.EMPTY;

        DynamicConfigModelV7 dynamicConfigModel = new DynamicConfigModelV7(
            doNotFailOnForbidden
                ? DNFOF_CONFIG.getSecurityConfiguration().getCEntry("config")
                : TEST_SECURITY_CONFIG.getSecurityConfiguration().getCEntry("config"),
            settings,
            null,
            null,
            null
        );
        ConfigModelV7 configModel = new ConfigModelV7(
            TEST_SECURITY_CONFIG.getRolesConfiguration(),
            TEST_SECURITY_CONFIG.getRoleMappingsConfiguration(),
            TEST_SECURITY_CONFIG.geActionGroupsConfiguration(),
            SecurityDynamicConfiguration.empty(),
            dynamicConfigModel,
            settings
        );

        PrivilegesEvaluator privilegesEvaluator = new PrivilegesEvaluator(
            clusterService,
            threadContext,
            configurationRepository,
            indexNameExpressionResolver,
            auditLog,
            settings,
            privilegesInterceptor,
            null,
            indexResolverReplacer,
            namedXContentRegistry
        );
        privilegesEvaluator.updateConfiguration(
            TEST_SECURITY_CONFIG.geActionGroupsConfiguration(),
            TEST_SECURITY_CONFIG.getRolesConfiguration()
        );
        privilegesEvaluator.onDynamicConfigModelChanged(dynamicConfigModel);
        privilegesEvaluator.onConfigModelChanged(configModel);

        return privilegesEvaluator;
    }

    static User user(TestSecurityConfig.User testUser) {
        User user = new User(testUser.getName());
        user.addSecurityRoles(testUser.getRoleNames());
        user.addAttributes(
            testUser.getAttributes()
                .entrySet()
                .stream()
                .map(e -> Map.entry("attr_internal_" + e.getKey(), e.getValue()))
                .collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue()))
        );
        return user;
    }

    static SortedMap<String, IndexAbstraction> testIndices(int count) {
        MockIndexMetadataBuilder builder = new MockIndexMetadataBuilder();
        char[] letters = new char[] { 'a', 'b', 'c', 'd', 'e' };
        int indicesPerLetter = count / letters.length;

        for (char c : letters) {
            for (int i = 0; i < indicesPerLetter; i++) {
                builder.index("index_" + c + "_" + i);
            }
        }

        return new TreeMap<>(builder.build());
    }

}
