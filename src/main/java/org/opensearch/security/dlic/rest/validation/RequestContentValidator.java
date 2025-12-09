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
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

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

import com.flipkart.zjsonpatch.JsonDiff;

import static org.opensearch.security.dlic.rest.api.Responses.payload;
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
        INTEGER,
        BOOLEAN;
    }

    /**
     * Validator interface for field-level validation
     */
    @FunctionalInterface
    public interface FieldValidator {
        /**
         * Validate a field value
         * @param fieldName the name of the field being validated
         * @param value the value to validate (can be String, JsonNode, etc.)
         * @throws IllegalArgumentException if validation fails
         */
        void validate(String fieldName, Object value);
    }

    /**
     * Configuration for a field including its type and validation rules
     */
    public static class FieldConfiguration {
        private final DataType dataType;
        private final Integer maxLength;
        private final FieldValidator validator;

        private FieldConfiguration(DataType dataType, Integer maxLength, FieldValidator validator) {
            this.dataType = dataType;
            this.maxLength = maxLength;
            this.validator = validator;
        }

        public static FieldConfiguration of(DataType dataType) {
            return new FieldConfiguration(dataType, null, null);
        }

        public static FieldConfiguration of(DataType dataType, int maxLength) {
            return new FieldConfiguration(dataType, maxLength, null);
        }

        public static FieldConfiguration of(DataType dataType, FieldValidator validator) {
            return new FieldConfiguration(dataType, null, validator);
        }

        public static FieldConfiguration of(DataType dataType, int maxLength, FieldValidator validator) {
            return new FieldConfiguration(dataType, maxLength, validator);
        }

        public DataType getDataType() {
            return dataType;
        }

        public Integer getMaxLength() {
            return maxLength;
        }

        public FieldValidator getValidator() {
            return validator;
        }

        public void validate(String fieldName, Object value) {
            // Validate max length for strings
            if (maxLength != null && value instanceof String strValue) {
                if (strValue.length() > maxLength) {
                    throw new IllegalArgumentException(fieldName + " length [" + strValue.length() + "] exceeds max [" + maxLength + "]");
                }
            }

            // Run custom validator if present
            if (validator != null) {
                validator.validate(fieldName, value);
            }
        }
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

        /**
         * Optional: Returns field configurations with validation rules.
         * If not overridden, returns null and the validator will use allowedKeys() instead.
         * This is an opt-in enhancement for more flexible validation.
         */
        default Map<String, FieldConfiguration> allowedKeysWithConfig() {
            return null;
        }

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

    public ValidationResult<JsonNode> validate(final RestRequest request, final JsonNode patchedContent, final JsonNode originalContent)
        throws IOException {
        JsonNode patch = JsonDiff.asJson(originalContent, patchedContent);
        if (patch.isEmpty()) {
            return ValidationResult.error(RestStatus.OK, payload(RestStatus.OK, "No updates required"));
        }
        return validateContentSize(patchedContent).map(this::validateJsonKeys)
            .map(this::validateDataType)
            .map(this::nullValuesInArrayValidator)
            .map(ignored -> validatePassword(request, patchedContent));
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

        // Use allowedKeysWithConfig if provided, otherwise fall back to allowedKeys
        final Map<String, FieldConfiguration> fieldConfigs = validationContext.allowedKeysWithConfig();
        final Set<String> allowed;
        if (fieldConfigs != null) {
            allowed = new HashSet<>(fieldConfigs.keySet());
        } else {
            allowed = new HashSet<>(validationContext.allowedKeys().keySet());
        }
        requestedKeys.removeAll(allowed);
        invalidKeys.addAll(requestedKeys);

        if (!missingMandatoryKeys.isEmpty() || !invalidKeys.isEmpty() || !missingMandatoryOrKeys.isEmpty()) {
            this.validationError = ValidationError.INVALID_CONFIGURATION;
            return ValidationResult.error(RestStatus.BAD_REQUEST, this);
        }
        return ValidationResult.success(jsonContent);
    }

    private ValidationResult<JsonNode> validateDataType(final JsonNode jsonContent) {
        // Check if enhanced validation is available
        final Map<String, FieldConfiguration> fieldConfigs = validationContext.allowedKeysWithConfig();
        final boolean useEnhancedValidation = (fieldConfigs != null);

        try (final JsonParser parser = DefaultObjectMapper.objectMapper.treeAsTokens(jsonContent)) {
            JsonToken token;
            while ((token = parser.nextToken()) != null) {
                if (token.equals(JsonToken.FIELD_NAME)) {
                    String currentName = parser.currentName();

                    // Get data type from either FieldConfiguration or simple DataType map
                    final DataType dataType;
                    final FieldConfiguration fieldConfig;

                    if (useEnhancedValidation && fieldConfigs != null) {
                        fieldConfig = fieldConfigs.get(currentName);
                        dataType = (fieldConfig != null) ? fieldConfig.getDataType() : null;
                    } else {
                        fieldConfig = null;
                        dataType = validationContext.allowedKeys().get(currentName);
                    }

                    if (dataType != null) {
                        JsonToken valueToken = parser.nextToken();

                        // Validate data type
                        switch (dataType) {
                            case INTEGER:
                                if (valueToken != JsonToken.VALUE_NUMBER_INT) {
                                    wrongDataTypes.put(currentName, "Integer expected");
                                }
                                break;
                            case STRING:
                                if (valueToken != JsonToken.VALUE_STRING) {
                                    wrongDataTypes.put(currentName, "String expected");
                                } else if (fieldConfig != null) {
                                    // Enhanced validation: validate string-specific constraints
                                    String stringValue = parser.getText();
                                    try {
                                        fieldConfig.validate(currentName, stringValue);
                                    } catch (IllegalArgumentException e) {
                                        wrongDataTypes.put(currentName, e.getMessage());
                                    }
                                }
                                break;
                            case ARRAY:
                                if (valueToken != JsonToken.START_ARRAY && valueToken != JsonToken.END_ARRAY) {
                                    wrongDataTypes.put(currentName, "Array expected");
                                } else if (fieldConfig != null && fieldConfig.getValidator() != null) {
                                    // Enhanced validation: validate array content
                                    JsonNode arrayNode = jsonContent.get(currentName);
                                    try {
                                        fieldConfig.validate(currentName, arrayNode);
                                    } catch (IllegalArgumentException e) {
                                        wrongDataTypes.put(currentName, e.getMessage());
                                    }
                                }
                                break;
                            case OBJECT:
                                if (!valueToken.equals(JsonToken.START_OBJECT) && !valueToken.equals(JsonToken.END_OBJECT)) {
                                    wrongDataTypes.put(currentName, "Object expected");
                                } else if (fieldConfig != null && fieldConfig.getValidator() != null) {
                                    // Enhanced validation: validate object content
                                    JsonNode objectNode = jsonContent.get(currentName);
                                    try {
                                        fieldConfig.validate(currentName, objectNode);
                                    } catch (IllegalArgumentException e) {
                                        wrongDataTypes.put(currentName, e.getMessage());
                                    }
                                }
                                break;
                            case BOOLEAN:
                                if (valueToken != JsonToken.VALUE_TRUE && valueToken != JsonToken.VALUE_FALSE) {
                                    // Backwards compatibility: accept string "true" or "false"
                                    if (valueToken == JsonToken.VALUE_STRING) {
                                        String strValue = parser.getText();
                                        if (!"true".equalsIgnoreCase(strValue) && !"false".equalsIgnoreCase(strValue)) {
                                            wrongDataTypes.put(currentName, "Boolean expected");
                                        }
                                    } else {
                                        wrongDataTypes.put(currentName, "Boolean expected");
                                    }
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
                if (hasNullOrBlankArrayElement(value)) {
                    this.validationError = ValidationError.NULL_ARRAY_ELEMENT;
                    return ValidationResult.error(RestStatus.BAD_REQUEST, this);
                }
            }
        }
        return ValidationResult.success(jsonContent);
    }

    private boolean hasNullOrBlankArrayElement(final JsonNode node) {
        for (final JsonNode element : node) {
            if (element.isNull() || (element.isTextual() && Strings.isNullOrEmpty(element.asText().trim()))) {
                if (node.isArray()) {
                    return true;
                }
            } else if (element.isContainerNode()) {
                if (hasNullOrBlankArrayElement(element)) {
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
            private final Map<String, FieldConfiguration> allowedKeysWithConfig = validationContext.allowedKeysWithConfig();

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

            @Override
            public Map<String, FieldConfiguration> allowedKeysWithConfig() {
                return allowedKeysWithConfig;
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
        NULL_ARRAY_ELEMENT("`null` or blank values are not allowed as json array elements");

        private final String message;

        private ValidationError(String message) {
            this.message = message;
        }

        public String message() {
            return message;
        }

    }

    /* ========================================================================
     * Input Validation Utilities (Generic)
     * ======================================================================== */

    public static final int MAX_STRING_LENGTH = 256;
    public static final int MAX_ARRAY_SIZE = 100_000;

    // Alphanumeric + _ - : OR : * - "*" is only allowed as standalone
    private static final Pattern SAFE_VALUE = Pattern.compile("^(\\*|[A-Za-z0-9_:-]+)$");

    /* ---------------------- generic helpers ---------------------- */

    public static void requireNonEmpty(String fieldName, String value) {
        if (Strings.isNullOrEmpty(value)) {
            throw new IllegalArgumentException(fieldName + " must not be null or empty");
        }
    }

    public static void validateMaxLength(String fieldName, String value, int maxLength) {
        if (value.length() > maxLength) {
            throw new IllegalArgumentException(fieldName + " length [" + value.length() + "] exceeds max [" + maxLength + "]");
        }
    }

    /**
     * Validates a value against safe character pattern with optional wildcard support
     * @param fieldName the name of the field being validated
     * @param value the value to validate
     * @param maxLength maximum allowed length
     * @param allowWildcard whether to allow "*" as a standalone value
     */
    public static void validateSafeValue(String fieldName, String value, int maxLength, boolean allowWildcard) {
        requireNonEmpty(fieldName, value);
        validateMaxLength(fieldName, value, maxLength);
        if (!SAFE_VALUE.matcher(value).matches()) {
            throw new IllegalArgumentException(
                fieldName + " contains invalid characters; allowed: " + (allowWildcard ? "* OR " : "") + "A-Z a-z 0-9 _ - :"
            );
        }
    }

    /**
     * Validates a value against safe character pattern (no wildcard support)
     */
    public static void validateSafeValue(String fieldName, String value, int maxLength) {
        validateSafeValue(fieldName, value, maxLength, false);
    }

    public static void validateArrayEntryCount(String fieldName, int count) {
        if (count > MAX_ARRAY_SIZE) {
            throw new IllegalArgumentException("Array field [" + fieldName + "] exceeds maximum size of " + MAX_ARRAY_SIZE);
        }
    }

    /**
     * Generic value validation against an allowed set (for types, levels, etc.)
     * @param fieldName the name of the field being validated
     * @param value the value to validate
     * @param maxLength maximum allowed length
     * @param allowedValues set or collection of allowed values
     */
    public static void validateValueInSet(String fieldName, String value, int maxLength, Collection<String> allowedValues) {
        validateSafeValue(fieldName, value, maxLength);

        if (allowedValues == null || allowedValues.isEmpty()) {
            throw new IllegalStateException("No allowed values configured for " + fieldName);
        }

        if (!allowedValues.contains(value)) {
            throw new IllegalArgumentException(
                "Invalid " + fieldName + " [" + value + "]. Allowed values: " + String.join(", ", allowedValues)
            );
        }
    }

    /* ---------------------- JSON extraction helpers ---------------------- */

    /**
     * Extracts a required text field from JSON with length validation
     */
    public static String getRequiredText(JsonNode body, String fieldName, int maxLength) {
        JsonNode node = body.get(fieldName);
        if (node == null || node.isNull() || !node.isTextual()) {
            throw new IllegalArgumentException("Field [" + fieldName + "] is required and must be a non-empty string");
        }
        String value = node.asText();
        requireNonEmpty(fieldName, value);
        validateMaxLength(fieldName, value, maxLength);
        return value;
    }

    /**
     * Extracts an optional text field from JSON with length validation
     */
    public static String getOptionalText(JsonNode body, String fieldName, int maxLength) {
        JsonNode node = body.get(fieldName);
        if (node == null || node.isNull()) {
            return null;
        }
        if (!node.isTextual()) {
            throw new IllegalArgumentException("Field [" + fieldName + "] must be a string when provided");
        }
        String value = node.asText();
        if (value.isEmpty()) {
            return null;
        }
        validateMaxLength(fieldName, value, maxLength);
        return value;
    }

    /* ---------------------- specialized validators ---------------------- */

    /**
     * Validates a path-like value (no whitespace allowed)
     */
    public static void validatePath(String fieldName, String path, int maxLength) {
        requireNonEmpty(fieldName, path);
        validateMaxLength(fieldName, path, maxLength);
        if (!path.equals(path.trim()) || path.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException(fieldName + " must not contain whitespace");
        }
    }

    /**
     * Validates a value against an allowed set
     */
    public static void validateFieldValueInSet(
        String fieldName,
        String value,
        int maxLength,
        Set<String> allowedValues,
        String errorContext
    ) {
        requireNonEmpty(fieldName, value);
        validateMaxLength(fieldName, value, maxLength);
        if (allowedValues == null || allowedValues.isEmpty()) {
            throw new IllegalStateException("No allowed " + errorContext + " configured");
        }
        if (!allowedValues.contains(value)) {
            throw new IllegalArgumentException("Invalid " + fieldName + " [" + value + "]. Allowed " + errorContext + ": " + allowedValues);
        }
    }

    /**
     * Validates a JSON object node with non-empty string values
     */
    public static void validateObjectWithStringValues(String fieldName, JsonNode node) {
        if (node == null || node.isNull()) {
            return;
        }

        if (!node.isObject()) {
            throw new IllegalArgumentException(fieldName + " must be an object");
        }

        if (!node.fieldNames().hasNext()) {
            throw new IllegalArgumentException(fieldName + " cannot be empty");
        }

        node.fields().forEachRemaining(entry -> {
            JsonNode val = entry.getValue();
            if (!val.isTextual() || val.asText().isEmpty()) {
                throw new IllegalArgumentException(fieldName + " for key [" + entry.getKey() + "] must be a non-empty string");
            }
        });
    }

    /* ========================================================================
     * Pre-built Field Validators for Common Use Cases
     * ======================================================================== */

    /**
     * Creates a validator for principal values (users, roles, backend_roles, etc.)
     * @param allowWildcard whether to allow "*" as a standalone value
     */
    public static FieldValidator principalValidator(boolean allowWildcard) {
        return (fieldName, value) -> {
            if (value instanceof String strValue) {
                validateSafeValue(fieldName, strValue, MAX_STRING_LENGTH, allowWildcard);
            }
        };
    }

    /**
     * Validator for path-like values (no whitespace allowed)
     */
    public static final FieldValidator PATH_VALIDATOR = (fieldName, value) -> {
        if (value instanceof String strValue) {
            validatePath(fieldName, strValue, MAX_STRING_LENGTH);
        }
    };

    /**
     * Validator for array entry counts (works with JsonNode arrays)
     */
    public static final FieldValidator ARRAY_SIZE_VALIDATOR = (fieldName, value) -> {
        if (value instanceof JsonNode node) {
            if (node.isArray() && node.size() > MAX_ARRAY_SIZE) {
                throw new IllegalArgumentException("Array field [" + fieldName + "] exceeds maximum size of " + MAX_ARRAY_SIZE);
            }
        } else if (value instanceof Integer) {
            int count = (Integer) value;
            if (count > MAX_ARRAY_SIZE) {
                throw new IllegalArgumentException("Array field [" + fieldName + "] exceeds maximum size of " + MAX_ARRAY_SIZE);
            }
        }
    };

    /**
     * Creates a validator that checks if a string value is in an allowed set
     */
    public static FieldValidator allowedValuesValidator(Set<String> allowedValues, String errorMessage) {
        return (fieldName, value) -> {
            if (value instanceof String strValue) {
                if (!allowedValues.contains(strValue)) {
                    throw new IllegalArgumentException(
                        errorMessage != null ? errorMessage : fieldName + " must be one of: " + String.join(", ", allowedValues)
                    );
                }
            }
        };
    }
}
