package org.opensearch.security.identity;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.identity.ScheduledJobIdentityManager;
import org.opensearch.identity.schedule.ScheduledJobIdentityModel;
import org.opensearch.identity.schedule.ScheduledJobOperator;
import org.opensearch.identity.schedule.ScheduledJobUserModel;
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.identity.tokens.BearerAuthToken;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
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
    public void saveUserDetails(String jobId, String indexName, ScheduledJobOperator operator) {
        if (!securityIndices.doesScheduledJobIdentityIndexExists()) {
           securityIndices.initScheduledJobIdentityIndex(ActionListener.wrap(response -> {
                if (response.isAcknowledged()) {
                    logger.info("Created {} with mappings.", SCHEDULED_JOB_IDENTITY_INDEX);
                    createScheduledJobIdentityEntry(jobId, indexName, operator);
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
            createScheduledJobIdentityEntry(jobId, indexName, operator);
        }
    }

    private void createScheduledJobIdentityEntry(String jobId, String indexName, ScheduledJobOperator operator) {
        SearchRequest searchRequest = new SearchRequest().indices(SCHEDULED_JOB_IDENTITY_INDEX);
        BoolQueryBuilder boolQuery = QueryBuilders.boolQuery()
                .must(QueryBuilders.matchQuery("job_id", jobId))
                .must(QueryBuilders.matchQuery("job_index", indexName));
        searchRequest.source(SearchSourceBuilder.searchSource().query(boolQuery));

        client.search(
            searchRequest,
            ActionListener
                .wrap(
                    response -> indexScheduledJobIdentity(response, jobId, indexName, operator),
                    exception -> new OpenSearchSecurityException(
                        "Exception received while querying for " + jobId + " in " + SCHEDULED_JOB_IDENTITY_INDEX
                    )
                )
        );
    }

    private void deleteScheduledJobIdentityEntry(String jobId, String indexName) {
        SearchRequest searchRequest = new SearchRequest().indices(SCHEDULED_JOB_IDENTITY_INDEX);
        BoolQueryBuilder boolQuery = QueryBuilders.boolQuery()
                .must(QueryBuilders.matchQuery("job_id", jobId))
                .must(QueryBuilders.matchQuery("job_index", indexName));
        searchRequest.source(SearchSourceBuilder.searchSource().query(boolQuery));

        client.search(
            searchRequest,
            ActionListener.wrap(
                response -> deleteScheduledJobIdentity(response, jobId, indexName),
                exception -> new OpenSearchSecurityException(
                    "Exception received while querying for " + jobId + " in " + SCHEDULED_JOB_IDENTITY_INDEX
                )
            )
        );
    }

    private void indexScheduledJobIdentity(
            SearchResponse response,
            String jobId,
            String indexName,
            ScheduledJobOperator operator
    ) throws IOException {
        long totalHits = response.getHits().getTotalHits().value;
        if (totalHits > 1) {
            // Should not happen
            logger.warn("Multiple scheduled job identities already exists in " + SCHEDULED_JOB_IDENTITY_INDEX + " for job with jobId " + jobId);
        } else if (totalHits == 1) {
            logger.info("Scheduled Job Identity already exists in " + SCHEDULED_JOB_IDENTITY_INDEX + " for job with jobId " + jobId);
        } else {
            ScheduledJobIdentityModel identity = operator.getIdentity();
            ScheduledJobUserModel userModel = identity.getUser();
            String username = userModel.getUsername();
            Map<String, String> attributes = userModel.getAttributes();
            if (!(attributes.containsKey("roles") && attributes.containsKey("backend_roles"))) {
                throw new OpenSearchSecurityException("Attempting to save user details for scheduled job, but user info is empty");
            }
            List<String> roles = Arrays.stream(attributes.get("roles").split(",")).collect(Collectors.toList());
            List<String> backendRoles = Arrays.stream(attributes.get("backend_roles").split(",")).collect(Collectors.toList());
            final User user = new User(username, backendRoles, roles, List.of(), null);
            ScheduledJobIdentity identityOfJob = new ScheduledJobIdentity(jobId, indexName, Instant.now(), Instant.now(), user);
            IndexRequest indexRequest = new IndexRequest(SCHEDULED_JOB_IDENTITY_INDEX)
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .source(identityOfJob.toXContent(XContentFactory.jsonBuilder(), XCONTENT_WITH_TYPE));
            client.index(
                indexRequest,
                ActionListener.wrap(
                    indexResponse -> logger.info("Successfully created scheduled job identity index entry for jobId " + jobId + " in index " + indexName),
                    exception -> new OpenSearchSecurityException(
                        "Exception received while indexing for " + jobId + " in " + SCHEDULED_JOB_IDENTITY_INDEX
                    )
                )
            );
        }
    }

    private void deleteScheduledJobIdentity(
            SearchResponse response,
            String jobId,
            String indexName
    ) {
        long totalHits = response.getHits().getTotalHits().value;
        if (totalHits > 1) {
            // Should not happen
            logger.warn("Multiple scheduled job identities already exists in " + SCHEDULED_JOB_IDENTITY_INDEX + " for job with jobId " + jobId + " in index " + indexName);
        } else if (totalHits == 0) {
            logger.info("No scheduled job identity found in " + SCHEDULED_JOB_IDENTITY_INDEX + " for job with jobId " + jobId + " in index " + indexName);
        } else {
            String docId = response.getHits().getHits()[0].getId();
            DeleteRequest deleteRequest = new DeleteRequest(SCHEDULED_JOB_IDENTITY_INDEX)
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .id(docId);
            client.delete(
                deleteRequest,
                ActionListener.wrap(
                    indexResponse -> logger.info("Successfully deleted scheduled job identity index entry for jobId " + jobId + " in index " + indexName),
                    exception -> new OpenSearchSecurityException(
                            "Exception received while deleting scheduled job identity entry for " + jobId + " in " + SCHEDULED_JOB_IDENTITY_INDEX
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
        deleteScheduledJobIdentityEntry(jobId, indexName);
    }

    @Override
    public AuthToken issueAccessTokenOnBehalfOfUser(String jobId, String indexName, Optional<String> extensionUniqueId) {
        if (!securityIndices.doesScheduledJobIdentityIndexExists()) {
            throw new OpenSearchSecurityException("Scheduled Job Identity Index (" + SCHEDULED_JOB_IDENTITY_INDEX + ") does not exist.");
        }
        BearerAuthToken bearerAuthToken = new BearerAuthToken("header.payload.signature");
        return bearerAuthToken;
    }
}
