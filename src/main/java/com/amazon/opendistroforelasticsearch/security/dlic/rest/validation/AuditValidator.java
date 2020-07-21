package com.amazon.opendistroforelasticsearch.security.dlic.rest.validation;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.auditlog.config.AuditConfig;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestRequest;

public class AuditValidator extends AbstractConfigurationValidator {

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
                DefaultObjectMapper.readTree(getContentAsNode(), AuditConfig.class);
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
