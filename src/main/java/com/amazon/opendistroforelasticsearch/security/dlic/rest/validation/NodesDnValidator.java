package com.amazon.opendistroforelasticsearch.security.dlic.rest.validation;

import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestRequest;

public class NodesDnValidator extends AbstractConfigurationValidator {

    public NodesDnValidator(final RestRequest request, boolean isSuperAdmin, final BytesReference ref, final Settings esSettings, Object... param) {
        super(request, ref, esSettings, param);
        this.payloadMandatory = true;

        allowedKeys.put("nodes_dn", DataType.ARRAY);
        mandatoryKeys.add("nodes_dn");
    }
}
