/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.sample.secure;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

import com.carrotsearch.randomizedtesting.RandomizedTest;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.Version;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.jobscheduler.JobSchedulerPlugin;
import org.opensearch.jobscheduler.spi.schedule.CronSchedule;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.plugins.PluginInfo;
import org.opensearch.sample.SampleResourcePlugin;
import org.opensearch.sample.scheduledjob.SampleSecureJobParameter;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;
import static org.awaitility.Awaitility.await;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SecureJobTests {

    public static final AuthcDomain AUTHC_DOMAIN = new AuthcDomain("basic", 0).httpAuthenticatorWithChallenge("basic").backend("internal");

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_DOMAIN)
        .users(USER_ADMIN)
        .plugin(JobSchedulerPlugin.class)
        .plugin(
            new PluginInfo(
                SampleResourcePlugin.class.getName(),
                "classpath plugin",
                "NA",
                Version.CURRENT,
                "1.8",
                SampleResourcePlugin.class.getName(),
                null,
                List.of(OpenSearchSecurityPlugin.class.getName(), JobSchedulerPlugin.class.getName()),
                false
            )
        )
        .nodeSettings(Map.of(SECURITY_SYSTEM_INDICES_ENABLED_KEY, true, "plugins.jobscheduler.sweeper.period", "1s"))
        .build();

    public static String randomAlphaOfLength(int codeUnits) {
        return RandomizedTest.randomAsciiOfLength(codeUnits);
    }

    protected Map<String, String> getJobParameterAsMap(String jobId, SampleSecureJobParameter jobParameter) throws IOException {
        Map<String, String> params = new HashMap<>();
        params.put("id", jobId);
        params.put("job_name", jobParameter.getName());
        params.put("index", jobParameter.getIndexToWatch());
        params.put("enabled", String.valueOf(jobParameter.isEnabled()));
        if (jobParameter.getSchedule() instanceof IntervalSchedule) {
            params.put("interval", String.valueOf(((IntervalSchedule) jobParameter.getSchedule()).getInterval()));
        } else if (jobParameter.getSchedule() instanceof CronSchedule) {
            params.put("cron", ((CronSchedule) jobParameter.getSchedule()).getCronExpression());
        }
        params.put("lock_duration_seconds", String.valueOf(jobParameter.getLockDurationSeconds()));
        return params;
    }

    public static String toUrlParams(Map<String, String> params) {
        StringJoiner joiner = new StringJoiner("&");
        for (Map.Entry<String, String> entry : params.entrySet()) {
            String encodedKey = URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8);
            String encodedValue = URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8);
            joiner.add(encodedKey + "=" + encodedValue);
        }
        return joiner.toString();
    }

    @Test
    public void testThatJobSchedulerIsInstalled() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.get("_cat/plugins");

            assertThat(response.getStatusCode(), equalTo(RestStatus.OK.getStatus()));
            assertThat(response.getBody(), containsString(JobSchedulerPlugin.class.getName()));
        }
    }

    @Test
    public void testCreateAJobAndWaitForCompletion() throws IOException {
        SampleSecureJobParameter jobParameter = new SampleSecureJobParameter();
        jobParameter.setJobName("sample-job-it");
        jobParameter.setIndexToWatch("http-logs");
        jobParameter.setSchedule(new IntervalSchedule(Instant.now(), 5, ChronoUnit.SECONDS));
        jobParameter.setLockDurationSeconds(5L);
        jobParameter.setEnabled(true);

        // Creates a new watcher job.
        String jobId = randomAlphaOfLength(10);
        Map<String, String> params = getJobParameterAsMap(jobId, jobParameter);
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.put("http-logs");
            HttpResponse response = client.post("_plugins/scheduler_sample/watch" + "?" + toUrlParams(params));

            assertThat(response.getStatusCode(), equalTo(RestStatus.OK.getStatus()));

            await().until(() -> {
                HttpResponse countResponse = client.get("http-logs/_count");
                return countResponse.getStatusCode() == RestStatus.OK.getStatus() && countResponse.getBody().contains("\"count\":1");
            });
        }
    }
}
