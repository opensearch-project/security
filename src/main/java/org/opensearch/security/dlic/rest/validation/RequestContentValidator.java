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

package org.opensearch.security.dlic.rest.validation;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.Strings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.DefaultObjectMapper;

import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE;

public class RequestContentValidator implements ToXContent {

    public final static RequestContentValidator NOOP_VALIDATOR = new RequestContentValidator(new ValidationContext() {
        @Override
        public Object[] params() {
            return new Object[0];
        }

        @Override
        public Settings settings() {
            return Settings.EMPTY;
        }

        @Override
        public Map<String, DataType> allowedKeys() {
            return Collections.emptyMap();
        }
    }) {
        @Override
        public ValidationResult<JsonNode> validate(RestRequest request) {
            return ValidationResult.success(DefaultObjectMapper.objectMapper.createObjectNode());
        }

        @Override
        public ValidationResult<JsonNode> validate(RestRequest request, JsonNode jsonNode) {
            return ValidationResult.success(DefaultObjectMapper.objectMapper.createObjectNode());
        }
    };

    public final static String INVALID_KEYS_KEY = "invalid_keys";

    /* public for testing */
    public final static String MISSING_MANDATORY_KEYS_KEY = "missing_mandatory_keys";

    /* public for testing */
    public final static String MISSING_MANDATORY_OR_KEYS_KEY = "specify_one_of";

    protected final static Logger LOGGER = LogManager.getLogger(RequestContentValidator.class);

    public static enum DataType {
        STRING,
        ARRAY,
        OBJECT,
        BOOLEAN;
    }

    public interface ValidationContext {

        default boolean hasParams() {
            return params() != null && params().length > 0;
        }

        default Set<String> mandatoryKeys() {
            return Collections.emptySet();
        }

        default Set<String> mandatoryOrKeys() {
            return Collections.emptySet();
        }

        Object[] params();

        Settings settings();

        Map<String, DataType> allowedKeys();

    }

    protected ValidationError validationError;

    protected final ValidationContext validationContext;

    protected final Map<String, String> wrongDataTypes = new HashMap<>();

    /** Contain errorneous keys */
    private final Set<String> missingMandatoryKeys = new HashSet<>();

    private final Set<String> invalidKeys = new HashSet<>();

    private final Set<String> missingMandatoryOrKeys = new HashSet<>();

    protected RequestContentValidator(final ValidationContext validationContext) {
        this.validationError = ValidationError.NONE;
        this.validationContext = validationContext;
    }

    public ValidationResult<JsonNode> validate(final RestRequest request) throws IOException {
        return parseRequestContent(request).map(this::validateContentSize).map(jsonContent -> validate(request, jsonContent));
    }

    public ValidationResult<JsonNode> validate(final RestRequest request, final JsonNode jsonContent) throws IOException {
        return validateContentSize(jsonContent).map(this::validateJsonKeys)
            .map(this::validateDataType)
            .map(this::nullValuesInArrayValidator)
            .map(ignored -> validatePassword(request, jsonContent));
    }

    private ValidationResult<JsonNode> parseRequestContent(final RestRequest request) {
        try {
            final JsonNode jsonContent = DefaultObjectMapper.readTree(request.content().utf8ToString());
            return ValidationResult.success(jsonContent);
        } catch (final IOException ioe) {
            this.validationError = ValidationError.BODY_NOT_PARSEABLE;
            return ValidationResult.error(RestStatus.BAD_REQUEST, this);
        }
    }

    protected ValidationResult<JsonNode> validateContentSize(final JsonNode jsonContent) {
        if (jsonContent.isEmpty()) {
            this.validationError = ValidationError.PAYLOAD_MANDATORY;
            return ValidationResult.error(RestStatus.BAD_REQUEST, this);
        }
        return ValidationResult.success(jsonContent);
    }

    protected ValidationResult<JsonNode> validateJsonKeys(final JsonNode jsonContent) {
        final Set<String> requestedKeys = new HashSet<>();
        jsonContent.fieldNames().forEachRemaining(requestedKeys::add);
        // mandatory settings, one of ...
        if (Collections.disjoint(requestedKeys, validationContext.mandatoryOrKeys())) {
            missingMandatoryOrKeys.addAll(validationContext.mandatoryOrKeys());
        }
        final Set<String> mandatory = new HashSet<>(validationContext.mandatoryKeys());
        mandatory.removeAll(requestedKeys);
        missingMandatoryKeys.addAll(mandatory);

        final Set<String> allowed = new HashSet<>(validationContext.allowedKeys().keySet());
        requestedKeys.removeAll(allowed);
        invalidKeys.addAll(requestedKeys);
        if (!missingMandatoryKeys.isEmpty() || !invalidKeys.isEmpty() || !missingMandatoryOrKeys.isEmpty()) {
            this.validationError = ValidationError.INVALID_CONFIGURATION;
            return ValidationResult.error(RestStatus.BAD_REQUEST, this);
        }
        return ValidationResult.success(jsonContent);
    }

    private ValidationResult<JsonNode> validateDataType(final JsonNode jsonContent) {
        try (final JsonParser parser = DefaultObjectMapper.objectMapper.treeAsTokens(jsonContent)) {
            JsonToken token;
            while ((token = parser.nextToken()) != null) {
                if (token.equals(JsonToken.FIELD_NAME)) {
                    String currentName = parser.getCurrentName();
                    final DataType dataType = validationContext.allowedKeys().get(currentName);
                    if (dataType != null) {
                        JsonToken valueToken = parser.nextToken();
                        switch (dataType) {
                            case STRING:
                                if (valueToken != JsonToken.VALUE_STRING) {
                                    wrongDataTypes.put(currentName, "String expected");
                                }
                                break;
                            case ARRAY:
                                if (valueToken != JsonToken.START_ARRAY && valueToken != JsonToken.END_ARRAY) {
                                    wrongDataTypes.put(currentName, "Array expected");
                                }
                                break;
                            case OBJECT:
                                if (!valueToken.equals(JsonToken.START_OBJECT) && !valueToken.equals(JsonToken.END_OBJECT)) {
                                    wrongDataTypes.put(currentName, "Object expected");
                                }
                                break;
                        }
                    }
                }
            }
        } catch (final IOException ioe) {
            LOGGER.error("Couldn't create JSON for payload {}", jsonContent, ioe);
            this.validationError = ValidationError.BODY_NOT_PARSEABLE;
            return ValidationResult.error(RestStatus.BAD_REQUEST, this);
        }
        if (!wrongDataTypes.isEmpty()) {
            this.validationError = ValidationError.WRONG_DATATYPE;
            return ValidationResult.error(RestStatus.BAD_REQUEST, this);
        }
        return ValidationResult.success(jsonContent);
    }

    private ValidationResult<JsonNode> nullValuesInArrayValidator(final JsonNode jsonContent) {
        for (final Map.Entry<String, DataType> allowedKey : validationContext.allowedKeys().entrySet()) {
            JsonNode value = jsonContent.get(allowedKey.getKey());
            if (value != null) {
                if (hasNullArrayElement(value)) {
                    this.validationError = ValidationError.NULL_ARRAY_ELEMENT;
                    return ValidationResult.error(RestStatus.BAD_REQUEST, this);
                }
            }
        }
        return ValidationResult.success(jsonContent);
    }

    private boolean hasNullArrayElement(final JsonNode node) {
        for (final JsonNode element : node) {
            if (element.isNull()) {
                if (node.isArray()) {
                    return true;
                }
            } else if (element.isContainerNode()) {
                if (hasNullArrayElement(element)) {
                    return true;
                }
            }
        }
        return false;
    }

    private ValidationResult<JsonNode> validatePassword(final RestRequest request, final JsonNode jsonContent) {
        if (jsonContent.has("password")) {
            final PasswordValidator passwordValidator = PasswordValidator.of(validationContext.settings());
            final String password = jsonContent.get("password").asText();
            if (Strings.isNullOrEmpty(password)) {
                this.validationError = ValidationError.INVALID_PASSWORD_TOO_SHORT;
                return ValidationResult.error(RestStatus.BAD_REQUEST, this);
            }
            final String username = Optional.ofNullable(request.param("name"))
                .orElseGet(() -> validationContext.hasParams() ? (String) validationContext.params()[0] : null);
            if (Strings.isNullOrEmpty(username)) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Unable to validate username because no user is given");
                }
                this.validationError = ValidationError.NO_USERNAME;
                return ValidationResult.error(RestStatus.BAD_REQUEST, this);
            }
            this.validationError = passwordValidator.validate(username, password);
            if (this.validationError != ValidationError.NONE) {
                return ValidationResult.error(RestStatus.BAD_REQUEST, this);
            }
        }
        return ValidationResult.success(jsonContent);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params) throws IOException {
        builder.startObject();
        switch (this.validationError) {
            case INVALID_CONFIGURATION:
                builder.field("status", "error");
                builder.field("reason", ValidationError.INVALID_CONFIGURATION.message());
                addErrorMessage(builder, INVALID_KEYS_KEY, invalidKeys);
                addErrorMessage(builder, MISSING_MANDATORY_KEYS_KEY, missingMandatoryKeys);
                addErrorMessage(builder, MISSING_MANDATORY_OR_KEYS_KEY, missingMandatoryOrKeys);
                break;
            case INVALID_PASSWORD_INVALID_REGEX:
                builder.field("status", "error");
                builder.field(
                    "reason",
                    validationContext.settings()
                        .get(SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE, "Password does not match minimum criteria")
                );
                break;
            case WRONG_DATATYPE:
                builder.field("status", "error");
                builder.field("reason", ValidationError.WRONG_DATATYPE.message());
                for (Map.Entry<String, String> entry : wrongDataTypes.entrySet()) {
                    builder.field(entry.getKey(), entry.getValue());
                }
                break;
            default:
                builder.field("status", "error");
                builder.field("reason", validationError.message());
                break;
        }
        builder.endObject();
        return builder;
    }

    private void addErrorMessage(final XContentBuilder builder, final String message, final Set<String> keys) throws IOException {
        if (!keys.isEmpty()) {
            builder.startObject(message).field("keys", String.join(",", keys)).endObject();
        }
    }

    public static RequestContentValidator of(final ValidationContext validationContext) {
        return new RequestContentValidator(new ValidationContext() {

            private final Object[] params = validationContext.params();

            private final Set<String> mandatoryKeys = validationContext.mandatoryKeys();

            private final Set<String> mandatoryOrKeys = validationContext.mandatoryOrKeys();

            private final Map<String, DataType> allowedKeys = validationContext.allowedKeys();

            @Override
            public Settings settings() {
                return validationContext.settings();
            }

            @Override
            public Object[] params() {
                return params;
            }

            @Override
            public Set<String> mandatoryKeys() {
                return mandatoryKeys;
            }

            @Override
            public Set<String> mandatoryOrKeys() {
                return mandatoryOrKeys;
            }

            @Override
            public Map<String, DataType> allowedKeys() {
                return allowedKeys;
            }
        });
    }

    public enum ValidationError {
        NONE("ok"),
        INVALID_CONFIGURATION("Invalid configuration"),
        INVALID_PASSWORD_TOO_SHORT("Password is too short"),
        INVALID_PASSWORD_TOO_LONG("Password is too long"),
        INVALID_PASSWORD_INVALID_REGEX("Password does not match validation regex"),
        NO_USERNAME("No username is given"),
        WEAK_PASSWORD("Weak password"),
        SIMILAR_PASSWORD("Password is similar to user name"),
        WRONG_DATATYPE("Wrong datatype"),
        BODY_NOT_PARSEABLE("Could not parse content of request."),
        PAYLOAD_NOT_ALLOWED("Request body not allowed for this action."),
        PAYLOAD_MANDATORY("Request body required for this action."),
        SECURITY_NOT_INITIALIZED("Security index not initialized"),
        NULL_ARRAY_ELEMENT("`null` is not allowed as json array element");

        private final String message;

        private ValidationError(String message) {
            this.message = message;
        }

        public String message() {
            return message;
        }

    }
}
