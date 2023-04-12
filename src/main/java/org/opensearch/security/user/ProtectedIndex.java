package org.opensearch.security.user;

import org.opensearch.security.support.ConfigConstants;
import static org.opensearch.security.support.ConfigConstants.TOKEN_INDEX_NAME;
import static org.opensearch.security.support.ConfigConstants.TOKEN_INDEX_SCHEMA_VERSION;


public class ProtectedIndex {


    public static final String TOKEN_INDEX_MAPPING = "{\n"
            + "    \"_meta\": {\"schema_version\": "
            + TOKEN_INDEX_SCHEMA_VERSION
            + "}\n}";

    public enum Indices {
        TOKEN(TOKEN_INDEX_NAME, false, TOKEN_INDEX_MAPPING, TOKEN_INDEX_SCHEMA_VERSION);

        private final String indexName;
        // whether we use an alias for the index
        private final boolean alias;
        private final String mapping;
        private final Integer version;

        Indices(String name, boolean alias, String mapping, Integer version) {
            this.indexName = name;
            this.alias = alias;
            this.mapping = mapping;
            this.version = version;
        }

        public String getIndexName() {
            return indexName;
        }

        public boolean isAlias() {
            return alias;
        }

        public String getMapping() {
            return mapping;
        }

        public Integer getVersion() {
            return version;
        }
    }
}
