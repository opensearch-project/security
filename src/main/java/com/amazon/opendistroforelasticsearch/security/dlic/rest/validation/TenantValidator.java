package com.amazon.opendistroforelasticsearch.security.dlic.rest.validation;



import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestRequest;

public class TenantValidator extends AbstractConfigurationValidator {

    public TenantValidator(final RestRequest request, BytesReference ref, final Settings esSettings, Object... param) {
        super(request, ref, esSettings, param);
        this.payloadMandatory = false;
        allowedKeys.put("description", DataType.STRING);
    }

}