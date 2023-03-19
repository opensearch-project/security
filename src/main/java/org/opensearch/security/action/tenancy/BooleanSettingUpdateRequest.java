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

public class BooleanSettingUpdateRequest extends ActionRequest {

    private Boolean value;

    public BooleanSettingUpdateRequest(final StreamInput in) throws IOException {
        super(in);
        in.readBoolean();
    }

    public BooleanSettingUpdateRequest(final Boolean value) {
        super();
        this.value = value;
    }

    public Boolean getValue() {
        return value;
    }

    @Override
    public ActionRequestValidationException validate() {
        if (getValue() == null) {
            final ActionRequestValidationException validationException = new ActionRequestValidationException();
            validationException.addValidationError("Missing boolean value");
            return validationException;
        }
        return null;
    }

    private static final ConstructingObjectParser<BooleanSettingUpdateRequest, Void> PARSER = new ConstructingObjectParser<>(
        BooleanSettingUpdateRequest.class.getName(),
        args -> new BooleanSettingUpdateRequest((Boolean) args[0])
    );

    static {
        PARSER.declareBoolean(ConstructingObjectParser.constructorArg(), new ParseField("value"));
    }

    public static BooleanSettingUpdateRequest fromXContent(final XContentParser parser) {
        return PARSER.apply(parser, null);
    }
}
