/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.sample.scheduledjob;

import java.util.UUID;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
import org.opensearch.jobscheduler.spi.utils.LockService;
import org.opensearch.plugins.Plugin;
import org.opensearch.transport.client.Client;

/**
 * A sample job runner class.
 *
 * The job runner should be a singleton class if it uses OpenSearch client or other objects passed
 * from OpenSearch. Because when registering the job runner to JobScheduler plugin, OpenSearch has
 * not invoke plugins' createComponents() method. That is saying the plugin is not completely initalized,
 * and the OpenSearch {@link Client}, {@link ClusterService} and other objects
 * are not available to plugin and this job runner.
 *
 * So we have to move this job runner intialization to {@link Plugin} createComponents() method, and using
 * singleton job runner to ensure we register a usable job runner instance to JobScheduler plugin.
 *
 * This sample job runner takes the "indexToWatch" from job parameter and logs that index's shards.
 */
public class SampleSecureJobRunner implements ScheduledJobRunner {

    private static final Logger log = LogManager.getLogger(ScheduledJobRunner.class);

    private static SampleSecureJobRunner INSTANCE;

    public static SampleSecureJobRunner getJobRunnerInstance() {
        if (INSTANCE != null) {
            return INSTANCE;
        }
        synchronized (SampleSecureJobRunner.class) {
            if (INSTANCE != null) {
                return INSTANCE;
            }
            INSTANCE = new SampleSecureJobRunner();
            return INSTANCE;
        }
    }

    private Client client;

    private SampleSecureJobRunner() {
        // Singleton class, use getJobRunner method instead of constructor
    }

    public void setClient(Client client) {
        this.client = client;
    }

    @Override
    public void runJob(ScheduledJobParameter jobParameter, JobExecutionContext context) {
        final LockService lockService = context.getLockService();

        if (jobParameter.getLockDurationSeconds() != null) {
            lockService.acquireLock(jobParameter, context, ActionListener.wrap(lock -> {
                if (lock == null) {
                    return;
                }

                SampleSecureJobParameter parameter = (SampleSecureJobParameter) jobParameter;
                this.client.indexAsync(
                    new IndexRequest(parameter.getIndexToWatch()).id(UUID.randomUUID().toString())
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                        .source("{\"message\": \"message\"}", XContentType.JSON)
                ).thenAccept(indexResponse -> {
                    lockService.release(
                        lock,
                        ActionListener.wrap(released -> { log.info("Released lock for job {}", jobParameter.getName()); }, exception -> {
                            throw new IllegalStateException("Failed to release lock.");
                        })
                    );
                }).exceptionally(exception -> { throw new IllegalStateException("Failed to index sample doc."); });
            }, exception -> { throw new IllegalStateException("Failed to acquire lock."); }));
        }
    }
}
