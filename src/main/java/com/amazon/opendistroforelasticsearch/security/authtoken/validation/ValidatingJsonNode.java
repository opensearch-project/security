package com.amazon.opendistroforelasticsearch.security.authtoken.validation;

import java.math.BigDecimal;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.temporal.TemporalAmount;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.TimeZone;
import java.util.function.Function;

import com.amazon.opendistroforelasticsearch.security.authtoken.parser.JsonNodeParser;
import com.amazon.opendistroforelasticsearch.security.authtoken.parser.ValueParser;
import com.amazon.opendistroforelasticsearch.security.util.temporal.DurationFormat;
import com.amazon.opendistroforelasticsearch.security.util.temporal.TemporalAmountFormat;
import org.apache.commons.validator.routines.EmailValidator;
import org.elasticsearch.common.unit.TimeValue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;


public class ValidatingJsonNode {
    private ValidationErrors validationErrors;
    private JsonNode jsonNode;
    private Set<String> unconsumedAttributes;
    private Set<String> consumedAttributes = new HashSet<>();

    public ValidatingJsonNode(JsonNode jsonNode, ValidationErrors validationErrors) {
        this.jsonNode = jsonNode;
        this.validationErrors = validationErrors;
        this.unconsumedAttributes = getAttributeNames(jsonNode);
    }

    public ValidatingJsonNode(ValidatingJsonNode vJsonNode, ValidationErrors validationErrors) {
        this.jsonNode = vJsonNode.jsonNode;
        this.validationErrors = validationErrors;
        this.unconsumedAttributes = vJsonNode.unconsumedAttributes;
        this.consumedAttributes = vJsonNode.consumedAttributes;
    }

    public void used(String... attributes) {
        for (String attribute : attributes) {
            consume(attribute);
        }
    }

    public void used(Set<String> attributes) {
        if (attributes != null) {
            for (String attribute : attributes) {
                consume(attribute);
            }
        }
    }

    public JsonNode get(String attribute) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            return jsonNode.get(attribute);
        } else {
            return null;
        }
    }

    public ValidatingJsonNode getValidatingJsonNode(String attribute) {
        JsonNode node = get(attribute);

        if (node != null) {
            ValidationErrors attributeValidationErrors = new ValidationErrors(validationErrors, attribute);

            return new ValidatingJsonNode(node, attributeValidationErrors);
        } else {
            return null;
        }
    }

    public ValidatingJsonNode getRequiredValidatingJsonNode(String attribute) {
        JsonNode node = get(attribute);

        if (node != null) {
            ValidationErrors attributeValidationErrors = new ValidationErrors(validationErrors, attribute);

            return new ValidatingJsonNode(node, attributeValidationErrors);
        } else {
            validationErrors.add(new MissingAttribute(attribute, jsonNode));
            return null;
        }
    }

    public ObjectNode getObjectNode(String attribute) {
        JsonNode attributeNode = get(attribute);

        if (attributeNode == null) {
            return null;
        } else if (attributeNode instanceof ObjectNode) {
            return (ObjectNode) attributeNode;
        } else {
            validationErrors.add(new InvalidAttributeValueError(attribute, attributeNode, "JSON object", attributeNode));
            return null;
        }
    }

    public boolean hasNonNull(String attribute) {
        consume(attribute);

        return jsonNode.hasNonNull(attribute);
    }

    public String requiredString(String attribute) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            return jsonNode.get(attribute).asText();
        } else {
            validationErrors.add(new MissingAttribute(attribute, jsonNode));
            return null;
        }
    }

    public int requiredInt(String attribute) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            JsonNode attributeNode = jsonNode.get(attribute);

            if (attributeNode.isNumber()) {
                return attributeNode.asInt();
            } else {
                validationErrors.add(new InvalidAttributeValueError(attribute, attributeNode.toString(), "number", attributeNode));
                return 0;
            }
        } else {
            validationErrors.add(new MissingAttribute(attribute, jsonNode));
            return 0;
        }
    }

    public long requiredLong(String attribute) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            JsonNode attributeNode = jsonNode.get(attribute);

            if (attributeNode.isNumber()) {
                return attributeNode.asLong();
            } else {
                validationErrors.add(new InvalidAttributeValueError(attribute, attributeNode.toString(), "number", attributeNode));
                return 0;
            }
        } else {
            validationErrors.add(new MissingAttribute(attribute, jsonNode));
            return 0;
        }
    }

    public BigDecimal requiredBigDecimal(String attribute) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            JsonNode attributeNode = jsonNode.get(attribute);

            if (attributeNode.isNumber()) {
                return attributeNode.decimalValue();
            } else {
                validationErrors.add(new InvalidAttributeValueError(attribute, attributeNode.toString(), "number", attributeNode));
                return null;
            }
        } else {
            validationErrors.add(new MissingAttribute(attribute, jsonNode));
            return null;
        }
    }

    public BigDecimal decimalValue(String attribute, BigDecimal defaultValue) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            JsonNode attributeNode = jsonNode.get(attribute);

            if (attributeNode.isNumber()) {
                return attributeNode.decimalValue();
            } else {
                validationErrors.add(new InvalidAttributeValueError(attribute, attributeNode.toString(), "number", attributeNode));
                return null;
            }
        } else {
            return defaultValue;
        }
    }

    public ArrayNode requiredArray(String attribute) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            JsonNode attributeNode = jsonNode.get(attribute);

            if (attributeNode instanceof ArrayNode) {
                return (ArrayNode) attributeNode;
            } else {
                validationErrors.add(new InvalidAttributeValueError(attribute, attributeNode.toString(), "Array", attributeNode));
                return null;
            }
        } else {
            validationErrors.add(new MissingAttribute(attribute, jsonNode));
            return null;
        }

    }

    public ObjectNode requiredObject(String attribute) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            JsonNode attributeNode = jsonNode.get(attribute);

            if (attributeNode instanceof ObjectNode) {
                return (ObjectNode) attributeNode;
            } else {
                validationErrors.add(new InvalidAttributeValueError(attribute, attributeNode.toString(), "Object", attributeNode));
                return null;
            }
        } else {
            validationErrors.add(new MissingAttribute(attribute, jsonNode));
            return null;
        }

    }

    public String string(String attribute) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            return jsonNode.get(attribute).asText();
        } else {
            return null;
        }
    }

    public String string(String attribute, String defaultValue) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            return jsonNode.get(attribute).asText();
        } else {
            return defaultValue;
        }
    }

    public String emailAddress(String attribute) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            String value = jsonNode.get(attribute).asText();

            if (EmailValidator.getInstance(true, true).isValid(value)) {
                return value;
            } else {
                validationErrors.add(new InvalidAttributeValueError(attribute, value, "E-mail address", jsonNode));
                return null;
            }
        } else {
            return null;
        }
    }

    public List<String> emailAddressList(String attribute) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            JsonNode subNode = jsonNode.get(attribute);
            List<String> result;

            if (subNode.isArray()) {
                ArrayNode arrayNode = (ArrayNode) subNode;
                result = new ArrayList<>(arrayNode.size());

                for (JsonNode child : arrayNode) {
                    result.add(child.asText());
                }

            } else {
                result = Collections.singletonList(subNode.textValue());
            }

            int errorCount = 0;

            for (String address : result) {
                if (!EmailValidator.getInstance(true, true).isValid(address)) {
                    validationErrors.add(new InvalidAttributeValueError(attribute, address, "E-mail address", jsonNode));
                    errorCount++;
                }
            }

            if (errorCount == 0) {
                return result;
            } else {
                return null;
            }

        } else {
            return null;
        }
    }

    public String[] emailAddressArray(String attribute) {
        consume(attribute);

        List<String> result = emailAddressList(attribute);

        if (result != null) {
            return result.toArray(new String[result.size()]);
        } else {
            return null;
        }
    }

    public Integer intNumber(String attribute, Integer defaultValue) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            JsonNode attributeNode = jsonNode.get(attribute);

            if (attributeNode.isNumber()) {
                return attributeNode.asInt();
            } else {
                return defaultValue;
            }
        } else {
            return defaultValue;
        }
    }

    public Long longNumber(String attribute, Long defaultValue) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            JsonNode attributeNode = jsonNode.get(attribute);

            if (attributeNode.isNumber()) {
                return attributeNode.asLong();
            } else {
                return defaultValue;
            }
        } else {
            return defaultValue;
        }
    }

    public Boolean booleanAttribute(String attribute, Boolean defaultValue) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            JsonNode attributeNode = jsonNode.get(attribute);

            if (attributeNode.isBoolean()) {
                return attributeNode.asBoolean();
            } else {
                return defaultValue;
            }
        } else {
            return defaultValue;
        }
    }

    public List<String> requiredStringList(String attribute, int minLength) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            List<String> result = stringList(attribute);

            if (result != null && result.size() < minLength) {
                if (minLength == 1) {
                    validationErrors.add(new InvalidAttributeValueError(attribute, jsonNode.get(attribute), "At least one element is required"));
                } else {
                    validationErrors
                            .add(new InvalidAttributeValueError(attribute, jsonNode.get(attribute), "At least " + minLength + " elements are required"));
                }
            }

            return result;
        } else {
            validationErrors.add(new MissingAttribute(attribute, jsonNode));
            return null;
        }
    }

    public List<String> stringList(String attribute) {
        return stringList(attribute, null);
    }

    public List<String> stringList(String attribute, List<String> defaultValue) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            JsonNode subNode = jsonNode.get(attribute);

            if (subNode.isArray()) {
                ArrayNode arrayNode = (ArrayNode) subNode;
                List<String> result = new ArrayList<>(arrayNode.size());

                for (JsonNode child : arrayNode) {
                    result.add(child.asText());
                }

                return result;
            } else {
                return Collections.singletonList(subNode.textValue());
            }

        } else {
            return defaultValue;
        }
    }

    public String[] stringArray(String attribute) {
        consume(attribute);

        List<String> list = stringList(attribute);

        if (list != null) {
            return list.toArray(new String[list.size()]);
        } else {
            return null;
        }
    }

    public TimeZone timeZone(String attribute) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            String timeZoneId = jsonNode.get(attribute).asText();

            TimeZone timeZone = TimeZone.getTimeZone(timeZoneId);

            if (timeZone == null) {
                validationErrors.add(new InvalidAttributeValueError(attribute, timeZoneId, TimeZone.class, jsonNode));
            }

            return timeZone;

        } else {
            return null;
        }
    }

    public Duration duration(String attribute) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            try {
                return DurationFormat.INSTANCE.parse(jsonNode.get(attribute).textValue());
            } catch (ConfigValidationException e) {
                validationErrors.add(attribute, e);
                return null;
            }
        } else {
            return null;
        }
    }

    public TemporalAmount temporalAmount(String attribute) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            try {
                return TemporalAmountFormat.INSTANCE.parse(jsonNode.get(attribute).textValue());
            } catch (ConfigValidationException e) {
                validationErrors.add(attribute, e);
                return null;
            }
        } else {
            return null;
        }
    }


    public TimeValue timeValue(String attribute) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            try {
                return TimeValue.parseTimeValue(jsonNode.get(attribute).textValue(), attribute);
            } catch (IllegalArgumentException e) {
                validationErrors.add(new InvalidAttributeValueError(attribute, jsonNode.get(attribute).textValue(), "<time value> (d|h|m|s|ms)"));
                return null;
            }
        } else {
            return null;
        }
    }

    public <R> R requiredValue(String attribute, Function<String, R> conversionFunction, Object expected) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            return value(attribute, conversionFunction, expected, null);
        } else {
            validationErrors.add(new MissingAttribute(attribute, jsonNode));
            return null;
        }
    }

    public <R> R value(String attribute, Function<String, R> conversionFunction, Object expected, R defaultValue) {
        consume(attribute);

        if (!jsonNode.hasNonNull(attribute)) {
            return defaultValue;
        }

        String value = jsonNode.get(attribute).asText();

        try {
            return conversionFunction.apply(value);
        } catch (Exception e) {
            validationErrors.add(new InvalidAttributeValueError(attribute, value, expected, jsonNode).cause(e));
            return defaultValue;
        }
    }

    public <R> R requiredValue(String attribute, ValueParser<R> valueParser) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            return value(attribute, valueParser, null);
        } else {
            validationErrors.add(new MissingAttribute(attribute, jsonNode));
            return null;
        }
    }

    public <R> R value(String attribute, ValueParser<R> valueParser, R defaultValue) {
        consume(attribute);

        if (!jsonNode.hasNonNull(attribute)) {
            return defaultValue;
        }

        String value = jsonNode.get(attribute).asText();

        try {
            return valueParser.parse(value);
        } catch (ConfigValidationException e) {
            validationErrors.add(attribute, e.getValidationErrors());
            return defaultValue;
        } catch (Exception e) {
            validationErrors.add(new InvalidAttributeValueError(attribute, value, valueParser.getExpectedValue(), jsonNode).cause(e));
            return defaultValue;
        }
    }


    public <R> R requiredValue(String attribute, JsonNodeParser<R> valueParser) {
        consume(attribute);

        if (jsonNode.hasNonNull(attribute)) {
            return value(attribute, valueParser, null);
        } else {
            validationErrors.add(new MissingAttribute(attribute, jsonNode));
            return null;
        }
    }

    public <R> R value(String attribute, JsonNodeParser<R> conversionFunction, R defaultValue) {
        consume(attribute);

        if (!jsonNode.hasNonNull(attribute)) {
            return defaultValue;
        }

        JsonNode subNode = jsonNode.get(attribute);

        try {
            return conversionFunction.parse(subNode);
        } catch (ConfigValidationException e) {
            validationErrors.add(attribute, e.getValidationErrors());
            return defaultValue;
        } catch (Exception e) {
            validationErrors.add(new InvalidAttributeValueError(attribute, subNode, conversionFunction.getExpectedValue(), jsonNode).cause(e));
            return defaultValue;
        }
    }

    public <R> List<R> list(String attribute, JsonNodeParser<R> conversionFunction) {
        return list(attribute, conversionFunction, Collections.emptyList());
    }

    public <R> List<R> list(String attribute, JsonNodeParser<R> conversionFunction, List<R> defaultValue) {
        consume(attribute);

        if (!jsonNode.hasNonNull(attribute)) {
            return defaultValue;
        }

        JsonNode value = jsonNode.get(attribute);

        if (!value.isArray()) {
            validationErrors.add(new InvalidAttributeValueError(attribute, value, "Array", jsonNode));
            return defaultValue;
        }

        ArrayNode arrayNode = (ArrayNode) value;

        List<R> result = new ArrayList<>(arrayNode.size());

        for (JsonNode elementNode : arrayNode) {

            try {
                result.add(conversionFunction.parse(elementNode));
            } catch (Exception e) {
                validationErrors.add(new InvalidAttributeValueError(attribute, value, null, jsonNode).cause(e));
                return defaultValue;
            }
        }

        return result;
    }

    public <E extends Enum<E>> E caseInsensitiveEnum(String attribute, Class<E> enumClass, E defaultValue) {
        consume(attribute);

        if (!jsonNode.hasNonNull(attribute)) {
            return defaultValue;
        }
        String value = jsonNode.get(attribute).asText();

        for (E e : enumClass.getEnumConstants()) {
            if (value.equalsIgnoreCase(e.name())) {
                return e;
            }
        }

        validationErrors.add(new InvalidAttributeValueError(attribute, value, enumClass, jsonNode));

        return defaultValue;
    }

    public <E extends Enum<E>> E requiredCaseInsensitiveEnum(String attribute, Class<E> enumClass) {
        if (!jsonNode.hasNonNull(attribute)) {
            validationErrors.add(new MissingAttribute(attribute, jsonNode));
            return null;
        }

        return caseInsensitiveEnum(attribute, enumClass, null);
    }


    public JsonNode getDelegate() {
        return jsonNode;
    }

    private Set<String> getAttributeNames(JsonNode jsonNode) {
        if (!(jsonNode instanceof ObjectNode)) {
            return new HashSet<>();
        }

        ObjectNode objectNode = (ObjectNode) jsonNode;

        Set<String> result = new HashSet<>(objectNode.size());

        for (Iterator<String> iter = objectNode.fieldNames(); iter.hasNext();) {
            result.add(iter.next());
        }

        return result;
    }

    private void consume(String attribute) {
        this.unconsumedAttributes.remove(attribute);
        this.consumedAttributes.add(attribute);
    }

}
