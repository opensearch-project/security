package org.opensearch.security.support;

import org.opensearch.action.admin.cluster.shards.ClusterSearchShardsAction;
import org.opensearch.action.admin.cluster.snapshots.restore.RestoreSnapshotAction;
import org.opensearch.action.admin.indices.alias.IndicesAliasesAction;
import org.opensearch.action.admin.indices.alias.get.GetAliasesAction;
import org.opensearch.action.admin.indices.close.CloseIndexAction;
import org.opensearch.action.admin.indices.create.AutoCreateAction;
import org.opensearch.action.admin.indices.delete.DeleteIndexAction;
import org.opensearch.action.admin.indices.mapping.get.GetFieldMappingsAction;
import org.opensearch.action.admin.indices.mapping.put.PutMappingAction;
import org.opensearch.action.admin.indices.resolve.ResolveIndexAction;
import org.opensearch.action.admin.indices.settings.get.GetSettingsAction;
import org.opensearch.action.admin.indices.settings.put.UpdateSettingsAction;
import org.opensearch.action.admin.indices.stats.IndicesStatsAction;
import org.opensearch.action.admin.indices.upgrade.post.UpgradeAction;
import org.opensearch.action.search.SearchAction;
import org.opensearch.action.index.IndexAction;
import org.opensearch.action.delete.DeleteAction;
import org.opensearch.action.search.SearchScrollAction;
import org.opensearch.action.bulk.BulkAction;
import org.opensearch.action.get.MultiGetAction;
import org.opensearch.action.search.MultiSearchAction;
import org.opensearch.action.termvectors.MultiTermVectorsAction;
import org.opensearch.action.update.UpdateAction;
import org.opensearch.action.admin.indices.create.CreateIndexAction;
import org.opensearch.action.admin.indices.mapping.put.AutoPutMappingAction;
import org.opensearch.index.reindex.ReindexAction;
import org.opensearch.script.mustache.RenderSearchTemplateAction;

/**
 * Constants defining patterns for various OpenSearch actions.
 * These patterns are used for permission checking and action filtering.
 */
public final class ActionPatternConstants {

    private ActionPatternConstants() {
        // Prevent instantiation
    }
    /**
     * Constants for index data operations (read/write)
     */
    public static final class IndicesData {
        /** Pattern matching all write operations on indices */
        public static final String WRITE_ALL = "indices:data/write/*";
        /** Pattern matching all read operations on indices */
        public static final String READ_ALL = "indices:data/read/*";

        private IndicesData() {}
    }

    /**
     * Constants for index administration operations
     */
    public static final class IndicesAdmin {
        public static final String DELETE_INDEX = DeleteIndexAction.NAME + "*";
        public static final String PUT_MAPPING = PutMappingAction.NAME + "*";
        public static final String UPDATE_SETTINGS = UpdateSettingsAction.NAME + "*";
        public static final String ALIASES = IndicesAliasesAction.NAME;
        public static final String CLOSE = CloseIndexAction.NAME + "*";
        public static final String GET_FIELD_MAPPINGS = GetFieldMappingsAction.NAME + "*";
        public static final String GET_ALIASES = GetAliasesAction.NAME + "*";
        public static final String RESOLVE_INDEX = ResolveIndexAction.NAME + "*";
        public static final String UPGRADE = UpgradeAction.NAME + "*";
        public static final String AUTO_CREATE = AutoCreateAction.NAME;
        public static final String AUTO_PUT_MAPPING = AutoPutMappingAction.NAME;
        public static final String CREATE_INDEX = CreateIndexAction.NAME;

        private IndicesAdmin() {}
    }

    /**
     * Constants for cluster-level operations
     */
    public static final class ClusterOperations {
        public static final String SNAPSHOT_RESTORE = RestoreSnapshotAction.NAME + "*";
        public static final String BASE_PATTERN = "cluster:";

        private ClusterOperations() {}
    }

    /**
     * Constants for monitoring operations
     */
    public static final class MonitorOperations {
        public static final String GET_SETTINGS = GetSettingsAction.NAME + "*";
        public static final String STATS = IndicesStatsAction.NAME + "*";

        private MonitorOperations() {}
    }

    /**
     * Constants for search-related operations
     */
    public static final class SearchOperations {
        public static final String SEARCH = SearchAction.NAME;
        public static final String SCROLL = SearchScrollAction.NAME;
        public static final String MULTI_SEARCH = MultiSearchAction.NAME;
        public static final String RENDER_TEMPLATE = RenderSearchTemplateAction.NAME;

        public static final String SEARCH_SHARDS = ClusterSearchShardsAction.NAME + "*";

        private SearchOperations() {}
    }

    /**
     * Constants for document-level operations
     */
    public static final class DocumentOperations {
        public static final String INDEX = IndexAction.NAME;
        public static final String DELETE = DeleteAction.NAME;
        public static final String BULK = BulkAction.NAME;
        public static final String MULTI_GET = MultiGetAction.NAME;
        public static final String MULTI_TERM_VECTORS = MultiTermVectorsAction.NAME;
        public static final String REINDEX = ReindexAction.NAME;
        public static final String UPDATE = UpdateAction.NAME;

        private DocumentOperations() {}
    }

    /**
     * Constants for template-related operations
     */
    public static final class TemplateOperations {
        public static final String ADMIN_TEMPLATE = "indices:admin/template/";
        public static final String ADMIN_INDEX_TEMPLATE = "indices:admin/index_template/";

        private TemplateOperations() {}
    }
}
