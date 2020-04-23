package com.amazon.opendistroforelasticsearch.security.securityconf.impl;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

public interface AuditModel {

    boolean isRestApiAuditEnabled();

    EnumSet<AuditCategory> getDisabledRestCategories();

    boolean isTransportApiAuditEnabled();

    EnumSet<AuditCategory> getDisabledTransportCategories();

    boolean shouldLogInternalConfig();

    boolean shouldLogExternalConfig();

    boolean shouldResolveBulkRequests();

    boolean shouldLogRequestBody();

    boolean shouldResolveIndices();

    boolean shouldExcludeSensitiveHeaders();

    Set<String> getIgnoredAuditUsers();

    Set<String> getIgnoredAuditRequests();

    Set<String> getImmutableIndicesPatterns();

    boolean shouldLogReadMetadataOnly();

    List<String> getReadWatchedFields();

    Set<String> getIgnoredComplianceUsersForRead();

    boolean shouldLogWriteMetadataOnly();

    boolean shouldLogDiffsForWrite();

    List<String> getWriteWatchedIndices();

    Set<String> getIgnoredComplianceUsersForWrite();

    String getSalt();
}
