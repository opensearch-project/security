package com.amazon.opendistroforelasticsearch.security.auditlog;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.amazon.opendistroforelasticsearch.security.securityconf.AuditModelImpl;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.Audit;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.AuditModel;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableSet;
import org.apache.http.Header;
import org.elasticsearch.common.settings.Settings;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public class AuditTestUtils {
    private static final List<String> DEFAULT_IGNORED_USERS = Collections.singletonList("kibanaserver");
    private static final List<String> DEFAULT_DISABLED_CATEGORIES =
            Arrays.asList(AuditCategory.AUTHENTICATED.toString(),
                    AuditCategory.GRANTED_PRIVILEGES.toString());

    public static void updateAuditConfig(final RestHelper rh, final Settings settings) throws Exception {
        updateAuditConfig(rh, AuditTestUtils.createAuditPayload(settings));
    }

    public static void updateAuditConfig(final RestHelper rh, final String payload) throws Exception {
        final boolean sendAdminCertificate = rh.sendAdminCertificate;
        final String keystore = rh.keystore;
        rh.sendAdminCertificate = true;
        rh.keystore = "auditlog/kirk-keystore.jks";
        RestHelper.HttpResponse response = rh.executePutRequest("_opendistro/_security/api/audit/config", payload, new Header[0]);
        System.out.println(response);
        rh.sendAdminCertificate = sendAdminCertificate;
        rh.keystore = keystore;
    }

    public static String createAuditPayload(final Settings settings) throws JsonProcessingException {
        final ObjectMapper objectMapper = new ObjectMapper();
        final Audit audit = AuditTestUtils.createAudit(settings);
        return objectMapper.writeValueAsString(audit);
    }

    public static String createAuditPayload(final Audit audit) throws JsonProcessingException {
        final ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.writeValueAsString(audit);
    }

    public static AuditModel createAuditModel(final Settings settings) {
        final Audit audit = createAudit(settings);
        return new AuditModelImpl(audit);
    }

    public static Audit createAudit(final Settings settings) {
        final Audit audit = new Audit();
        audit.setEnableRest(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true));
        audit.setEnableTransport(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true));
        audit.setResolveBulkRequests(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false));
        audit.setLogRequestBody(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, true));
        audit.setResolveIndices(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES, true));
        audit.setExcludeSensitiveHeaders(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS, true));
        audit.setExternalConfigEnabled(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false));
        audit.setInternalConfigEnabled(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, false));
        audit.setReadMetadataOnly(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_METADATA_ONLY, false));
        audit.setWriteMetadataOnly(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY, false));
        audit.setWriteLogDiffs(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, false));
        audit.setDisabledRestCategories(AuditCategory.parse(getSettingAsSet(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES,
                DEFAULT_DISABLED_CATEGORIES,
                true)));
        audit.setDisabledTransportCategories(AuditCategory.parse(getSettingAsSet(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES,
                DEFAULT_DISABLED_CATEGORIES,
                true)));
        audit.setIgnoreUsers(getSettingAsSet(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS,
                DEFAULT_IGNORED_USERS,
                false));
        audit.setReadIgnoreUsers(getSettingAsSet(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS,
                DEFAULT_IGNORED_USERS,
                false));
        audit.setWriteIgnoreUsers(getSettingAsSet(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS,
                DEFAULT_IGNORED_USERS,
                false));
        audit.setIgnoreRequests(ImmutableSet.copyOf(settings.getAsList(
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS,
                Collections.emptyList())));
        audit.setReadWatchedFields(settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS,
                Collections.emptyList(), false));
        audit.setWriteWatchedIndices(settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, Collections.emptyList()));
        audit.setImmutableIndices(ImmutableSet.copyOf(settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_IMMUTABLE_INDICES, Collections.emptyList())));

        return audit;
    }

    private static Set<String> getSettingAsSet(final Settings settings, final String key, final List<String> defaultList, final boolean ignoreCaseForNone) {
        final List<String> list = settings.getAsList(key, defaultList);
        if (list.size() == 1 && "NONE".equals(ignoreCaseForNone? list.get(0).toUpperCase() : list.get(0))) {
            return Collections.emptySet();
        }
        return ImmutableSet.copyOf(list);
    }
}
