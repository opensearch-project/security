package org.opensearch.security.identity;

import java.io.IOException;
import java.time.Instant;

import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.identity.ScheduledJobIdentityManager;
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.identity.SecurityIndices.SCHEDULED_JOB_IDENTITY_INDEX;

public class SecurityScheduledJobIdentityManager implements ScheduledJobIdentityManager {
    protected Logger logger = LogManager.getLogger(getClass());
    public static final ToXContent.MapParams XCONTENT_WITH_TYPE = new ToXContent.MapParams(ImmutableMap.of("with_type", "true"));

    private final ClusterService cs;

    private final Client client;

    private final ThreadPool threadPool;

    private final SecurityIndices securityIndices;

    public SecurityScheduledJobIdentityManager(ClusterService cs, Client client, ThreadPool threadPool) {
        this.cs = cs;
        this.client = client;
        this.threadPool = threadPool;
        this.securityIndices = new SecurityIndices(client, cs);
    }

    @Override
    public void saveUserDetails(String jobId, String indexName) {
        if (!securityIndices.doesScheduledJobIdentityIndexExists()) {
           securityIndices.initScheduledJobIdentityIndex(ActionListener.wrap(response -> {
                if (response.isAcknowledged()) {
                    logger.info("Created {} with mappings.", SCHEDULED_JOB_IDENTITY_INDEX);
                    createScheduledJobIdentityEntry(jobId, indexName);
                } else {
                    logger.warn("Created {} with mappings call not acknowledged.", SCHEDULED_JOB_IDENTITY_INDEX);
                    throw new OpenSearchSecurityException(
                        "Created " + SCHEDULED_JOB_IDENTITY_INDEX + " with mappings call not acknowledged."
                    );
                }
           }, exception -> new OpenSearchSecurityException(
               "Created " + SCHEDULED_JOB_IDENTITY_INDEX + " with mappings call failed."
           )));
        } else {
            createScheduledJobIdentityEntry(jobId, indexName);
        }
    }

    private void createScheduledJobIdentityEntry(String jobId, String indexName) {
        SearchRequest searchRequest = new SearchRequest().indices(SCHEDULED_JOB_IDENTITY_INDEX);
        BoolQueryBuilder boolQuery = QueryBuilders.boolQuery()
                .must(QueryBuilders.matchQuery("job_id", jobId))
                .must(QueryBuilders.matchQuery("job_index", indexName));
        searchRequest.source(SearchSourceBuilder.searchSource().query(boolQuery));

        client.search(
            searchRequest,
            ActionListener
                .wrap(
                    response -> indexScheduledJobIdentity(response, jobId, indexName),
                    exception -> new OpenSearchSecurityException(
                        "Exception received while querying for " + jobId + " in " + SCHEDULED_JOB_IDENTITY_INDEX
                    )
                )
        );
    }

    private void indexScheduledJobIdentity(
            SearchResponse response,
            String jobId,
            String indexName
    ) throws IOException {
        long totalHits = response.getHits().getTotalHits().value;
        if (totalHits > 1) {
            // Should not happen
            logger.warn("Multiple scheduled job identities already exists in " + SCHEDULED_JOB_IDENTITY_INDEX + " for job with jobId " + jobId);
        } else if (totalHits == 1) {
            logger.info("Scheduled Job Identity already exists in " + SCHEDULED_JOB_IDENTITY_INDEX + " for job with jobId " + jobId);
        } else {
            final User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
            if (user == null) {
                throw new OpenSearchSecurityException("Attempting to save user details for scheduled job, but user info is empty");
            }
            ScheduledJobIdentity identityOfJob = new ScheduledJobIdentity(jobId, indexName, Instant.now(), Instant.now(), user);
            XContentBuilder source = identityOfJob.toXContent(XContentFactory.jsonBuilder(), XCONTENT_WITH_TYPE);
            IndexRequest indexRequest = new IndexRequest(SCHEDULED_JOB_IDENTITY_INDEX)
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .source(identityOfJob.toXContent(XContentFactory.jsonBuilder(), XCONTENT_WITH_TYPE));
            client.index(
                indexRequest,
                ActionListener.wrap(
                    indexResponse -> logger.info("Successfully created scheduled job identity index entry for jobId " + jobId),
                    exception -> new OpenSearchSecurityException(
                        "Exception received while indexing for " + jobId + " in " + SCHEDULED_JOB_IDENTITY_INDEX
                    )
                )
            );
        }
    }

    @Override
    public void deleteUserDetails(String jobId, String indexName) {
        if (!securityIndices.doesScheduledJobIdentityIndexExists()) {
            throw new OpenSearchSecurityException("Scheduled Job Identity Index (" + SCHEDULED_JOB_IDENTITY_INDEX + ") does not exist.");
        }
    }

    @Override
    public AuthToken issueAccessTokenOnBehalfOfUser(String jobId, String indexName) {
        if (!securityIndices.doesScheduledJobIdentityIndexExists()) {
            throw new OpenSearchSecurityException("Scheduled Job Identity Index (" + SCHEDULED_JOB_IDENTITY_INDEX + ") does not exist.");
        }
        return null;
    }
}
