package org.opensearch.security.identity;

import java.io.IOException;
import java.net.URL;
import java.util.EnumMap;

import com.google.common.io.Resources;
import org.apache.commons.codec.Charsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;

import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.client.AdminClient;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.threadpool.ThreadPool;

public class SecurityIndices {
    protected Logger logger = LogManager.getLogger(getClass());

    public final static String SCHEDULED_JOB_IDENTITY_INDEX = ".opendistro-security-scheduled-job-identity";
    public static final String SCHEDULED_JOB_IDENTITY_INDEX_MAPPING_FILE = "mappings/scheduled-job-identity.json";
    static final String META = "_meta";
    private static final String SCHEMA_VERSION = "schema_version";
    public static Integer NO_SCHEMA_VERSION = 0;
    // minimum shards of the scheduled job identity index
    public static int minJobIndexReplicas = 1;
    // maximum shards of the scheduled job identity index
    public static int maxJobIndexReplicas = 20;

    private ClusterService clusterService;
    private final Client client;
    private final AdminClient adminClient;
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

    /**
     * Constructor function
     *
     * @param client         ES client supports administrative actions
     * @param clusterService ES cluster service
     * @param threadPool     ES thread pool
     */
    public SecurityIndices(
            Client client,
            ClusterService clusterService,
            ThreadPool threadPool
    ) {
        this.client = client;
        this.adminClient = client.admin();
        this.clusterService = clusterService;
        this.threadPool = threadPool;

        this.indexStates = new EnumMap<SecurityIndex, IndexState>(SecurityIndex.class);
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
            // since this method is called in the constructor that is called by OpenSearchSecurityPlugin.createComponents,
            // we cannot throw checked exception
            throw new RuntimeException(e);
        }
    }

    /**
     * Create scheduled job identity index.
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
            logger.error("Fail to init scheduler job identity index", e);
            actionListener.onFailure(e);
        }
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
}
