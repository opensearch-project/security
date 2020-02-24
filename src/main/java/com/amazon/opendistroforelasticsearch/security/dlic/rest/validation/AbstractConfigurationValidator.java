/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.dlic.rest.validation;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.google.common.base.Joiner;

public abstract class AbstractConfigurationValidator {

    JsonFactory factory = new JsonFactory();

    /* public for testing */
    public final static String INVALID_KEYS_KEY = "invalid_keys";

    /* public for testing */
    public final static String MISSING_MANDATORY_KEYS_KEY = "missing_mandatory_keys";

    /* public for testing */
    public final static String MISSING_MANDATORY_OR_KEYS_KEY = "specify_one_of";

    protected final Logger log = LogManager.getLogger(this.getClass());

    /** Define the various keys for this validator */
    protected final Map<String, DataType> allowedKeys = new HashMap<>();

    protected final Set<String> mandatoryKeys = new HashSet<>();

    protected final Set<String> mandatoryOrKeys = new HashSet<>();

    protected final Map<String, String> wrongDatatypes = new HashMap<>();

    /** Contain errorneous keys */
    protected final Set<String> missingMandatoryKeys = new HashSet<>();

    protected final Set<String> invalidKeys = new HashSet<>();

    protected final Set<String> missingMandatoryOrKeys = new HashSet<>();

    /** The error type */
    protected ErrorType errorType = ErrorType.NONE;

    /** Behaviour regarding payload */
    protected boolean payloadMandatory = false;

    protected boolean payloadAllowed = true;

    private Settings.Builder settingsBuilder;

    protected final Method method;

    protected final BytesReference content;

    protected final Settings esSettings;

    protected final RestRequest request;

    protected final Object[] param;

    public AbstractConfigurationValidator(final RestRequest request, final BytesReference ref, final Settings esSettings, Object... param) {
        this.content = ref;
        this.method = request.method();
        this.esSettings = esSettings;
        this.request = request;
        this.param = param;
    }

    /**
     *
     * @return false if validation fails
     */
    public boolean validateSettings() {
        // no payload for DELETE and GET requests
        if (method.equals(Method.DELETE) || method.equals(Method.GET)) {
            return true;
        }
        // try to parse payload
        try {
            this.settingsBuilder = toSettingsBuilder(content);
        } catch (ElasticsearchException e) {
            this.errorType = ErrorType.BODY_NOT_PARSEABLE;
            return false;
        }

        Settings settings = settingsBuilder.build();

        Set<String> requested = new HashSet<String>(settings.names());
        // check if payload is accepted at all
        if (!this.payloadAllowed && !requested.isEmpty()) {
            this.errorType = ErrorType.PAYLOAD_NOT_ALLOWED;
            return false;
        }
        // check if payload is mandatory
        if (this.payloadMandatory && requested.isEmpty()) {
            this.errorType = ErrorType.PAYLOAD_MANDATORY;
            return false;
        }

        // mandatory settings, one of ...
        if (Collections.disjoint(requested, mandatoryOrKeys)) {
            this.missingMandatoryOrKeys.addAll(mandatoryOrKeys);
        }

        // mandatory settings
        Set<String> mandatory = new HashSet<>(mandatoryKeys);
        mandatory.removeAll(requested);
        missingMandatoryKeys.addAll(mandatory);

        // invalid settings
        Set<String> allowed = new HashSet<>(allowedKeys.keySet());
        requested.removeAll(allowed);
        this.invalidKeys.addAll(requested);

        boolean valid = missingMandatoryKeys.isEmpty() && invalidKeys.isEmpty() && missingMandatoryOrKeys.isEmpty();
        if (!valid) {
            this.errorType = ErrorType.INVALID_CONFIGURATION;
        }

        // check types
        try {
            if (!checkDatatypes()) {
                this.errorType = ErrorType.WRONG_DATATYPE;
                return false;
            }
        } catch (Exception e) {
            this.errorType = ErrorType.BODY_NOT_PARSEABLE;
            return false;
        }

        return valid;
    }

    private boolean checkDatatypes() throws Exception {
        String contentAsJson = XContentHelper.convertToJson(content, false, XContentType.JSON);
        try (JsonParser parser = factory.createParser(contentAsJson)) {
            JsonToken token = null;
            while ((token = parser.nextToken()) != null) {
                if (token.equals(JsonToken.FIELD_NAME)) {
                    String currentName = parser.getCurrentName();
                    DataType dataType = allowedKeys.get(currentName);
                    if (dataType != null) {
                        JsonToken valueToken = parser.nextToken();
                        switch (dataType) {
                            case STRING:
                                if (!valueToken.equals(JsonToken.VALUE_STRING)) {
                                    wrongDatatypes.put(currentName, "String expected");
                                }
                                break;
                            case ARRAY:
                                if (!valueToken.equals(JsonToken.START_ARRAY) && !valueToken.equals(JsonToken.END_ARRAY)) {
                                    wrongDatatypes.put(currentName, "Array expected");
                                }
                                break;
                            case OBJECT:
                                if (!valueToken.equals(JsonToken.START_OBJECT) && !valueToken.equals(JsonToken.END_OBJECT)) {
                                    wrongDatatypes.put(currentName, "Object expected");
                                }
                                break;
                        }
                    }
                }
            }
            return wrongDatatypes.isEmpty();
        }
    }

    public XContentBuilder errorsAsXContent(RestChannel channel) {
        try {
            final XContentBuilder builder = channel.newBuilder();
            builder.startObject();
            switch (this.errorType) {
                case NONE:
                    builder.field("status", "error");
                    builder.field("reason", errorType.getMessage());
                    break;
                case INVALID_CONFIGURATION:
                    builder.field("status", "error");
                    builder.field("reason", ErrorType.INVALID_CONFIGURATION.getMessage());
                    addErrorMessage(builder, INVALID_KEYS_KEY, invalidKeys);
                    addErrorMessage(builder, MISSING_MANDATORY_KEYS_KEY, missingMandatoryKeys);
                    addErrorMessage(builder, MISSING_MANDATORY_OR_KEYS_KEY, missingMandatoryKeys);
                    break;
                case INVALID_PASSWORD:
                    builder.field("status", "error");
                    builder.field("reason", esSettings.get(ConfigConstants.OPENDISTRO_SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE,
                            "Password does not match minimum criterias"));
                    break;
                case WRONG_DATATYPE:
                    builder.field("status", "error");
                    builder.field("reason", ErrorType.WRONG_DATATYPE.getMessage());
                    for (Entry<String, String> entry : wrongDatatypes.entrySet()) {
                        builder.field(entry.getKey(), entry.getValue());
                    }
                    break;
                default:
                    builder.field("status", "error");
                    builder.field("reason", errorType.getMessage());
            }
            builder.endObject();
            return builder;
        } catch (IOException ex) {
            log.error("Cannot build error settings", ex);
            return null;
        }
    }

    public Settings.Builder settingsBuilder() {
        return settingsBuilder;
    }

    private void addErrorMessage(final XContentBuilder builder, final String message, final Set<String> keys) throws IOException {
        if (!keys.isEmpty()) {
            builder.startObject(message);
            builder.field("keys", Joiner.on(",").join(keys.toArray(new String[0])));
            builder.endObject();
        }
    }

    private Settings.Builder toSettingsBuilder(final BytesReference ref) {
        if (ref == null || ref.length() == 0) {
            return Settings.builder();
        }

        try {
            return Settings.builder().loadFromSource(ref.utf8ToString(), XContentType.JSON);
        } catch (final Exception e) {
            throw ExceptionsHelper.convertToElastic(e);
        }
    }

    public static enum DataType {
        STRING, ARRAY, OBJECT, BOOLEAN;
    }

    public static enum ErrorType {
        NONE("ok"), INVALID_CONFIGURATION("Invalid configuration"), INVALID_PASSWORD("Invalid password"), WRONG_DATATYPE("Wrong datatype"),
        BODY_NOT_PARSEABLE("Could not parse content of request."), PAYLOAD_NOT_ALLOWED("Request body not allowed for this action."),
        PAYLOAD_MANDATORY("Request body required for this action."), OPENDISTRO_SECURITY_NOT_INITIALIZED("Open Distro Security index not initialized.");

        private String message;

        private ErrorType(String message) {
            this.message = message;
        }

        public String getMessage() {
            return message;
        }
    }

    protected final boolean hasParams() {
        return param != null && param.length > 0;
    }
}