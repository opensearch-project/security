package com.amazon.opendistroforelasticsearch.security.dlic.rest.validation;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.Audit;
import com.google.common.collect.ImmutableList;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.compress.NotXContentException;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.rest.RestRequest;

import java.util.Collection;
import java.util.List;
import java.util.Map;

public class AuditValidator extends AbstractConfigurationValidator {

    private static final List<Tuple<String, DataType>> KEYS = ImmutableList.of(
            // rest
            new Tuple<>(Audit.Key.ENABLE_REST, DataType.BOOLEAN),
            new Tuple<>(Audit.Key.DISABLED_REST_CATEGORIES, DataType.ARRAY),

            // transport
            new Tuple<>(Audit.Key.ENABLE_TRANSPORT, DataType.BOOLEAN),
            new Tuple<>(Audit.Key.DISABLED_TRANSPORT_CATEGORIES, DataType.ARRAY),

            // attributes
            new Tuple<>(Audit.Key.RESOLVE_BULK_REQUESTS, DataType.BOOLEAN),
            new Tuple<>(Audit.Key.LOG_REQUEST_BODY, DataType.BOOLEAN),
            new Tuple<>(Audit.Key.RESOLVE_INDICES, DataType.BOOLEAN),
            new Tuple<>(Audit.Key.EXCLUDE_SENSITIVE_HEADERS, DataType.BOOLEAN),

            // config
            new Tuple<>(Audit.Key.INTERNAL_CONFIG_ENABLED, DataType.BOOLEAN),
            new Tuple<>(Audit.Key.EXTERNAL_CONFIG_ENABLED, DataType.BOOLEAN),

            // ignore
            new Tuple<>(Audit.Key.IGNORE_USERS, DataType.ARRAY),
            new Tuple<>(Audit.Key.IGNORE_REQUESTS, DataType.ARRAY),

            // compliance read
            new Tuple<>(Audit.Key.READ_METADATA_ONLY, DataType.BOOLEAN),
            new Tuple<>(Audit.Key.READ_WATCHED_FIELDS, DataType.ARRAY),
            new Tuple<>(Audit.Key.READ_IGNORE_USERS, DataType.ARRAY),

            // compliance write
            new Tuple<>(Audit.Key.WRITE_LOG_DIFFS, DataType.BOOLEAN),
            new Tuple<>(Audit.Key.WRITE_METADATA_ONLY, DataType.BOOLEAN),
            new Tuple<>(Audit.Key.WRITE_WATCHED_INDICES, DataType.ARRAY),
            new Tuple<>(Audit.Key.WRITE_IGNORE_USERS, DataType.ARRAY),

            // immutable
            new Tuple<>(Audit.Key.IMMUTABLE_INDICES, DataType.ARRAY),

            // salt
            new Tuple<>(Audit.Key.SALT, DataType.STRING)
    );

    public AuditValidator(final RestRequest request,
                          final BytesReference ref,
                          final Settings esSettings,
                          final Object... param) {
        super(request, ref, esSettings, param);
        KEYS.forEach(x -> allowedKeys.put(x.v1(), x.v2()));
    }

    @Override
    public boolean validate() {
        if (!super.validate()) {
            return false;
        }

        if ((request.method() == RestRequest.Method.PUT || request.method() == RestRequest.Method.PATCH)
                && this.content != null
                && this.content.length() > 1) {
            try {
                final Map<String, Object> contentAsMap = XContentHelper.convertToMap(this.content, false, XContentType.JSON).v2();
                if (contentAsMap != null) {
                    // validate the audit categories
                    if (!validateAuditCategories(contentAsMap)) {
                        this.errorType = ErrorType.BODY_NOT_PARSEABLE;
                        return false;
                    }
                    // validate salt
                    if (!validateSalt(contentAsMap)) {
                        this.errorType = ErrorType.INVALID_SALT;
                        return false;
                    }
                }
            } catch (NotXContentException e) {
                //this.content is not valid json/yaml
                log.error("Invalid xContent: " + e, e);
                return false;
            }
        }

        return true;
    }

    private boolean validateAuditCategories(final Map<String, Object> contentAsMap) {
        for (String key: ImmutableList.of(Audit.Key.DISABLED_REST_CATEGORIES, Audit.Key.DISABLED_TRANSPORT_CATEGORIES)) {
            try {
                if (contentAsMap.containsKey(key)) {
                    AuditCategory.parse((Collection<String>) contentAsMap.get(key));
                }
            } catch (Exception e) {
                log.error("Could not parse body of key {}", key);
                return false;
            }
        }
        return true;
    }

    private boolean validateSalt(final Map<String, Object> contentAsMap) {
        if (contentAsMap.containsKey(Audit.Key.SALT)) {
            final String salt = (String) contentAsMap.get(Audit.Key.SALT);
            return salt != null && salt.length() >= 16;
        }
        return true;
    }
}
