package com.amazon.opendistroforelasticsearch.security.securityconf;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.Audit;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.AuditModel;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

public class AuditModelImpl implements AuditModel {

    private final Audit audit;

    public AuditModelImpl(SecurityDynamicConfiguration<?> configuration) {
        this.audit = ((SecurityDynamicConfiguration<Audit>) configuration).getCEntry("config");
    }

    public AuditModelImpl(Audit audit) {
        this.audit = audit;
    }

    @Override
    public boolean isRestApiAuditEnabled() {
        return audit.isEnableRest();
    }

    @Override
    public EnumSet<AuditCategory> getDisabledRestCategories() {
        return audit.getDisabledRestCategories();
    }

    @Override
    public boolean isTransportApiAuditEnabled() {
        return audit.isEnableTransport();
    }

    @Override
    public EnumSet<AuditCategory> getDisabledTransportCategories() {
        return audit.getDisabledTransportCategories();
    }

    @Override
    public boolean shouldLogInternalConfig() {
        return audit.isInternalConfigEnabled();
    }

    @Override
    public boolean shouldLogExternalConfig() {
        return audit.isExternalConfigEnabled();
    }

    @Override
    public boolean shouldResolveBulkRequests() {
        return audit.isResolveBulkRequests();
    }

    @Override
    public boolean shouldLogRequestBody() {
        return audit.isLogRequestBody();
    }

    @Override
    public boolean shouldResolveIndices() {
        return audit.isResolveIndices();
    }

    @Override
    public boolean shouldExcludeSensitiveHeaders() {
        return audit.isExcludeSensitiveHeaders();
    }

    @Override
    public Set<String> getIgnoredAuditUsers() {
        return audit.getIgnoreUsers();
    }

    @Override
    public Set<String> getIgnoredAuditRequests() {
        return audit.getIgnoreRequests();
    }

    @Override
    public Set<String> getImmutableIndicesPatterns() {
        return audit.getImmutableIndices();
    }

    @Override
    public boolean shouldLogReadMetadataOnly() {
        return audit.isReadMetadataOnly();
    }

    @Override
    public List<String> getReadWatchedFields() {
        return audit.getReadWatchedFields();
    }

    @Override
    public Set<String> getIgnoredComplianceUsersForRead() {
        return audit.getReadIgnoreUsers();
    }

    @Override
    public boolean shouldLogWriteMetadataOnly() {
        return audit.isWriteMetadataOnly();
    }

    @Override
    public boolean shouldLogDiffsForWrite() {
        return audit.isWriteLogDiffs();
    }

    @Override
    public List<String> getWriteWatchedIndices() {
        return audit.getWriteWatchedIndices();
    }

    @Override
    public Set<String> getIgnoredComplianceUsersForWrite() {
        return audit.getWriteIgnoreUsers();
    }

    @Override
    public String getSalt() {
        return audit.getSalt();
    }
}
