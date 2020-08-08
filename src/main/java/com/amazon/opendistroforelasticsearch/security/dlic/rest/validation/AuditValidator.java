package com.amazon.opendistroforelasticsearch.security.dlic.rest.validation;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.auditlog.config.AuditConfig;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.google.common.collect.ImmutableSet;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestRequest;

import java.util.Set;

public class AuditValidator extends AbstractConfigurationValidator {

    private static final Set<AuditCategory> DISABLED_REST_CATEGORIES = ImmutableSet.of(
            AuditCategory.BAD_HEADERS,
            AuditCategory.SSL_EXCEPTION,
            AuditCategory.AUTHENTICATED,
            AuditCategory.FAILED_LOGIN,
            AuditCategory.GRANTED_PRIVILEGES,
            AuditCategory.MISSING_PRIVILEGES
    );

    private static final Set<AuditCategory> DISABLED_TRANSPORT_CATEGORIES = ImmutableSet.of(
            AuditCategory.BAD_HEADERS,
            AuditCategory.SSL_EXCEPTION,
            AuditCategory.AUTHENTICATED,
            AuditCategory.FAILED_LOGIN,
            AuditCategory.GRANTED_PRIVILEGES,
            AuditCategory.MISSING_PRIVILEGES,
            AuditCategory.INDEX_EVENT,
            AuditCategory.OPENDISTRO_SECURITY_INDEX_ATTEMPT
    );

    public AuditValidator(final RestRequest request,
                          final BytesReference ref,
                          final Settings esSettings,
                          final Object... param) {
        super(request, ref, esSettings, param);
        this.payloadMandatory = true;
        this.allowedKeys.put("enabled", DataType.BOOLEAN);
        this.allowedKeys.put("audit", DataType.OBJECT);
        this.allowedKeys.put("compliance", DataType.OBJECT);
    }

    @Override
    public boolean validate() {
        if (!super.validate()) {
            return false;
        }

        if ((request.method() == RestRequest.Method.PUT || request.method() == RestRequest.Method.PATCH)
                && this.content != null
                && this.content.length() > 0) {
            try {
                // try parsing to target type
                final AuditConfig auditConfig = DefaultObjectMapper.readTree(getContentAsNode(), AuditConfig.class);
                final AuditConfig.Filter filter = auditConfig.getFilter();
                if (!DISABLED_REST_CATEGORIES.containsAll(filter.getDisabledRestCategories())) {
                    throw new IllegalArgumentException("Invalid REST categories passed in the request");
                }
                if (!DISABLED_TRANSPORT_CATEGORIES.containsAll(filter.getDisabledTransportCategories())) {
                    throw new IllegalArgumentException("Invalid transport categories passed in the request");
                }
            } catch (Exception e) {
                // this.content is not valid json
                this.errorType = ErrorType.BODY_NOT_PARSEABLE;
                log.error("Invalid content passed in the request", e);
                return false;
            }
        }
        return true;
    }
}
