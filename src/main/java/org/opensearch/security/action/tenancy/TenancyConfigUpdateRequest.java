/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.action.tenancy;
import java.io.IOException;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.core.ParseField;
import org.opensearch.core.xcontent.ConstructingObjectParser;
import org.opensearch.core.xcontent.XContentParser;

public class TenancyConfigUpdateRequest extends ActionRequest {

    private TenancyConfigs tenancyConfigs = new TenancyConfigs();

    public TenancyConfigUpdateRequest(final StreamInput in) throws IOException {
        super(in);
        in.readOptionalBoolean();
        in.readOptionalBoolean();
        in.readOptionalString();
    }

    public TenancyConfigUpdateRequest(final Boolean multitenancy_enabled, final Boolean private_tenant_enabled, final String default_tenant) {
        super();
        this.tenancyConfigs.multitenancy_enabled = multitenancy_enabled;
        this.tenancyConfigs.private_tenant_enabled = private_tenant_enabled;
        this.tenancyConfigs.default_tenant = default_tenant;
    }

    public TenancyConfigs getTenancyConfigs() {
        return tenancyConfigs;
    }

    @Override
    public ActionRequestValidationException validate() {
        if (getTenancyConfigs() == null) {
            final ActionRequestValidationException validationException = new ActionRequestValidationException();
            validationException.addValidationError("Missing tenancy configs");
            return validationException;
        }
        return null;
    }

    private static final ConstructingObjectParser<TenancyConfigUpdateRequest, Void> PARSER = new ConstructingObjectParser<>(
            TenancyConfigUpdateRequest.class.getName(),
            args -> new TenancyConfigUpdateRequest((Boolean)args[0], (Boolean) args[1], (String) args[2])
    );

    static {
        PARSER.declareBoolean(ConstructingObjectParser.optionalConstructorArg(), new ParseField("multitenancy_enabled"));
        PARSER.declareBoolean(ConstructingObjectParser.optionalConstructorArg(), new ParseField("private_tenant_enabled"));
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), new ParseField("default_tenant"));

    }

    public static TenancyConfigUpdateRequest fromXContent(final XContentParser parser) {
        return PARSER.apply(parser, null);
    }
}
