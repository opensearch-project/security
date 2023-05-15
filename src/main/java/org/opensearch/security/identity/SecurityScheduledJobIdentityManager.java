package org.opensearch.security.identity;

import java.io.IOException;
import java.net.URL;
import java.time.Instant;
import java.util.EnumMap;

import com.google.common.collect.ImmutableMap;
import com.google.common.io.Resources;
import org.apache.commons.codec.Charsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.identity.ScheduledJobIdentityManager;
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

public class SecurityScheduledJobIdentityManager implements ScheduledJobIdentityManager {
    protected Logger logger = LogManager.getLogger(getClass());

    public final static String SCHEDULED_JOB_IDENTITY_INDEX = ".opendistro-security-scheduled-job-identity";
    public static final String SCHEDULED_JOB_IDENTITY_INDEX_MAPPING_FILE = "mappings/scheduled-job-identity.json";

    static final String META = "_meta";
    private static final String SCHEMA_VERSION = "schema_version";
    public static Integer NO_SCHEMA_VERSION = 0;
    public static final ToXContent.MapParams XCONTENT_WITH_TYPE = new ToXContent.MapParams(ImmutableMap.of("with_type", "true"));
    // minimum shards of the scheduled job identity index
    public static int minJobIndexReplicas = 1;
    // maximum shards of the scheduled job identity index
    public static int maxJobIndexReplicas = 20;

    private final ClusterService cs;

    private final Client client;

    private final ThreadPool threadPool;
    // keep track of whether the mapping version is up-to-date
    private EnumMap<SecurityIndex, IndexState> indexStates;

    class IndexState {
        // keep track of whether the mapping version is up-to-date
        private Boolean mappingUpToDate;
        // keep track of whether the setting needs to change
        private Boolean settingUpToDate;
        // record schema version reading from the mapping file
        private Integer schemaVersion;

        IndexState(SecurityIndex index) {
            this.mappingUpToDate = false;
            settingUpToDate = false;
            this.schemaVersion = parseSchemaVersion(index.getMapping());
        }
    }

    public SecurityScheduledJobIdentityManager(ClusterService cs, Client client, ThreadPool threadPool) {
        this.cs = cs;
        this.client = client;
        this.indexStates = new EnumMap<SecurityIndex, IndexState>(SecurityIndex.class);
        this.threadPool = threadPool;
    }

    private static Integer parseSchemaVersion(String mapping) {
        try {
            XContentParser xcp = XContentType.JSON
                    .xContent()
                    .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, mapping);

            while (!xcp.isClosed()) {
                XContentParser.Token token = xcp.currentToken();
                if (token != null && token != XContentParser.Token.END_OBJECT && token != XContentParser.Token.START_OBJECT) {
                    if (xcp.currentName() != META) {
                        xcp.nextToken();
                        xcp.skipChildren();
                    } else {
                        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
                            if (xcp.currentName().equals(SCHEMA_VERSION)) {

                                Integer version = xcp.intValue();
                                if (version < 0) {
                                    version = NO_SCHEMA_VERSION;
                                }
                                return version;
                            } else {
                                xcp.nextToken();
                            }
                        }

                    }
                }
                xcp.nextToken();
            }
            return NO_SCHEMA_VERSION;
        } catch (Exception e) {
            // since this method is called in the constructor that is called by AnomalyDetectorPlugin.createComponents,
            // we cannot throw checked exception
            throw new RuntimeException(e);
        }
    }

    protected boolean doesScheduledJobIdentityIndexExists() {
        if (!cs.state().metadata().hasConcreteIndex(SCHEDULED_JOB_IDENTITY_INDEX)) {
            return false;
        }
        return true;
    }

    /**
     * Get scheduled job identity index mapping json content.
     *
     * @return scheduled job identity index mapping
     * @throws IOException IOException if mapping file can't be read correctly
     */
    public static String getScheduledJobIdentityMappings() throws IOException {
        URL url = SecurityScheduledJobIdentityManager.class.getClassLoader().getResource(SCHEDULED_JOB_IDENTITY_INDEX_MAPPING_FILE);
        return Resources.toString(url, Charsets.UTF_8);
    }

    private ActionListener<CreateIndexResponse> markMappingUpToDate(SecurityIndex index, ActionListener<CreateIndexResponse> followingListener) {
        return ActionListener.wrap(createdResponse -> {
            if (createdResponse.isAcknowledged()) {
                IndexState indexState = indexStates.computeIfAbsent(index, IndexState::new);
                if (Boolean.FALSE.equals(indexState.mappingUpToDate)) {
                    indexState.mappingUpToDate = Boolean.TRUE;
                    logger.info(new ParameterizedMessage("Mark [{}]'s mapping up-to-date", index.getIndexName()));
                }
            }
            followingListener.onResponse(createdResponse);
        }, exception -> followingListener.onFailure(exception));
    }

    /**
     * Create anomaly detector job index.
     *
     * @param actionListener action called after create index
     */
    public void initScheduledJobIdentityIndex(ActionListener<CreateIndexResponse> actionListener) {
        try {
            CreateIndexRequest request = new CreateIndexRequest(SCHEDULED_JOB_IDENTITY_INDEX)
                    .mapping(getScheduledJobIdentityMappings(), XContentType.JSON);
            request
                    .settings(
                            Settings
                                    .builder()
                                    // Schedule job identity index is small. 1 primary shard is enough
                                    .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
                                    // Job scheduler puts both primary and replica shards in the
                                    // hash ring. Auto-expand the number of replicas based on the
                                    // number of data nodes (up to 20) in the cluster so that each node can
                                    // become a coordinating node. This is useful when customers
                                    // scale out their cluster so that we can do adaptive scaling
                                    // accordingly.
                                    // At least 1 replica for fail-over.
                                    .put(IndexMetadata.SETTING_AUTO_EXPAND_REPLICAS, minJobIndexReplicas + "-" + maxJobIndexReplicas)
                                    .put("index.hidden", true)
                    );
            client.admin().indices().create(request, markMappingUpToDate(SecurityIndex.SCHEDULED_JOB_IDENTITY, actionListener));
        } catch (IOException e) {
            logger.error("Fail to init AD job index", e);
            actionListener.onFailure(e);
        }
    }

    @Override
    public void saveUserDetails(String jobId, String indexName) {
        if (!doesScheduledJobIdentityIndexExists()) {
           initScheduledJobIdentityIndex(ActionListener.wrap(response -> {
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
        // TODO Figure out if jobId is unique across indexes since jobs details are stored in indices
        // owned by different plugins
        GetRequest getRequest = new GetRequest(SCHEDULED_JOB_IDENTITY_INDEX).id(jobId);

        client.get(
            getRequest,
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
            GetResponse response,
            String jobId,
            String indexName
    ) throws IOException {
        if (response.isExists()) {
            logger.info("Scheduled Job Identity already exists in " + SCHEDULED_JOB_IDENTITY_INDEX + " for job with jobId " + jobId);
        } else {
            final User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
            System.out.println("Saving job identity with user " + user);
            if (user == null) {
                throw new OpenSearchSecurityException("Attempting to save user details for scheduled job, but user info is empty");
            }
            ScheduledJobIdentity identityOfJob = new ScheduledJobIdentity(indexName, Instant.now(), Instant.now(), user);
            System.out.println("identityOfJob: " + identityOfJob);
            XContentBuilder source = identityOfJob.toXContent(XContentFactory.jsonBuilder(), XCONTENT_WITH_TYPE);
            System.out.println("source: " + source);
            IndexRequest indexRequest = new IndexRequest(SCHEDULED_JOB_IDENTITY_INDEX)
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .source(identityOfJob.toXContent(XContentFactory.jsonBuilder(), XCONTENT_WITH_TYPE))
                    .id(jobId);
            System.out.println("Index Request: " + indexRequest);
            client
                    .index(
                            indexRequest,
                            ActionListener
                                    .wrap(
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
        if (!doesScheduledJobIdentityIndexExists()) {
            throw new OpenSearchSecurityException("Scheduled Job Identity Index (" + SCHEDULED_JOB_IDENTITY_INDEX + ") does not exist.");
        }
    }

    @Override
    public AuthToken issueAccessTokenOnBehalfOfUser(String jobId, String indexName) {
        if (!doesScheduledJobIdentityIndexExists()) {
            throw new OpenSearchSecurityException("Scheduled Job Identity Index (" + SCHEDULED_JOB_IDENTITY_INDEX + ") does not exist.");
        }
        return null;
    }
}
