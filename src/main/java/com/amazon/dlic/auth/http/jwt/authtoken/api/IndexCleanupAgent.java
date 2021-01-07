package com.amazon.dlic.auth.http.jwt.authtoken.api;

import java.util.function.Supplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.ClusterChangedEvent;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.ClusterStateListener;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.component.Lifecycle;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.index.IndexNotFoundException;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.index.reindex.BulkByScrollResponse;
import org.elasticsearch.index.reindex.DeleteByQueryAction;
import org.elasticsearch.index.reindex.DeleteByQueryRequestBuilder;
import org.elasticsearch.threadpool.Scheduler.Cancellable;
import org.elasticsearch.threadpool.ThreadPool;

public class IndexCleanupAgent {

    private final static Logger log = LogManager.getLogger(IndexCleanupAgent.class);
    private final static Supplier<QueryBuilder> DEFAULT_CLEANUP_QUERY = () -> QueryBuilders.rangeQuery("expires").lt(System.currentTimeMillis());

    private final Client client;
    private final ThreadPool threadPool;
    private final String index;
    private final Supplier<QueryBuilder> cleanupQuery;
    private final ClusterService clusterService;

    private Cancellable cleanupJob;
    private TimeValue cleanupInterval = TimeValue.timeValueHours(1);

    private volatile boolean cleanupInProgress;
    private volatile long cleanupInProgressSince;

    public IndexCleanupAgent(String indexName, Supplier<QueryBuilder> cleanupQuery, TimeValue cleanupInterval, Client client,
                             ClusterService clusterService, ThreadPool threadPool) {
        this.client = client;
        this.threadPool = threadPool;
        this.index = indexName;
        this.cleanupQuery = cleanupQuery;
        this.clusterService = clusterService;
        this.cleanupInterval = cleanupInterval;

        if (clusterService.lifecycleState() == Lifecycle.State.STARTED) {
            checkState(clusterService.state());
        }

        clusterService.addListener(clusterStateListener);
    }

    public IndexCleanupAgent(String indexName, TimeValue cleanupInterval, Client client, ClusterService clusterService, ThreadPool threadPool) {
        this(indexName, DEFAULT_CLEANUP_QUERY, cleanupInterval, client, clusterService, threadPool);
    }

    public IndexCleanupAgent(String indexName, String expiresColumnName, TimeValue cleanupInterval, Client client, ClusterService clusterService,
                             ThreadPool threadPool) {
        this(indexName, () -> QueryBuilders.rangeQuery(expiresColumnName).lt(System.currentTimeMillis()), cleanupInterval, client, clusterService,
                threadPool);
    }

    private void cleanupExpiredEntries() {
        if (cleanupInProgress) {
            log.warn("Cleanup for " + index + " is still in progress since " + (System.currentTimeMillis() - cleanupInProgressSince)
                    + " ms. Skipping next cleanup");
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("Starting cleanup for " + index + ". Interval: " + cleanupInterval);
        }

        cleanupInProgress = true;
        cleanupInProgressSince = System.currentTimeMillis();

        try {
            new DeleteByQueryRequestBuilder(client, DeleteByQueryAction.INSTANCE).filter(cleanupQuery.get()).source(index)
                    .execute(new ActionListener<BulkByScrollResponse>() {
                        @Override
                        public void onResponse(BulkByScrollResponse response) {
                            cleanupInProgress = false;

                            long deleted = response.getDeleted();

                            log.debug("Deleted " + deleted + " expired entries from " + index);
                        }

                        @Override
                        public void onFailure(Exception e) {
                            cleanupInProgress = false;

                            if (e instanceof IndexNotFoundException) {
                                log.debug("No expired entries have been deleted because the index does not exist", e);
                            } else {
                                log.error("Error while deleting expired entries from " + index, e);
                            }
                        }
                    });
        } catch (Exception e) {
            cleanupInProgress = false;

            log.error("Error while starting cleanup", e);
        }
    }

    private final ClusterStateListener clusterStateListener = new ClusterStateListener() {

        @Override
        public void clusterChanged(ClusterChangedEvent event) {
            checkState(event.state());
        }

    };

    private void checkState(ClusterState clusterState) {
        boolean isMaster = clusterState.nodes().isLocalNodeElectedMaster();

        if (isMaster && cleanupJob == null) {
            synchronized (IndexCleanupAgent.this) {
                if (cleanupJob == null) {
                    cleanupJob = threadPool.scheduleWithFixedDelay(() -> cleanupExpiredEntries(), cleanupInterval, ThreadPool.Names.GENERIC);
                }
            }
        } else if (!isMaster && cleanupJob != null) {
            synchronized (IndexCleanupAgent.this) {
                if (cleanupJob != null) {
                    cleanupJob.cancel();
                    cleanupJob = null;
                    cleanupInProgress = false;
                }
            }
        }
    }

    public TimeValue getCleanupInterval() {
        return cleanupInterval;
    }

    public void shutdown() {
        clusterService.removeListener(clusterStateListener);

        synchronized (this) {
            if (cleanupJob != null) {
                cleanupJob.cancel();
                cleanupJob = null;
                cleanupInProgress = false;
            }
        }
    }
}

