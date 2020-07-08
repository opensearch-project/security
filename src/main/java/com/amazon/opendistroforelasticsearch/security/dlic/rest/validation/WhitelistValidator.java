package com.amazon.opendistroforelasticsearch.security.dlic.rest.validation;

import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestRequest;

public class WhitelistValidator extends AbstractConfigurationValidator {

    public WhitelistValidator(final RestRequest request, final BytesReference ref, final Settings esSettings, Object... param) {
        super(request, ref, esSettings, param);
        this.payloadMandatory = true;
        allowedKeys.put("enabled", DataType.BOOLEAN);
        allowedKeys.put("requests", DataType.OBJECT);
    }
}
