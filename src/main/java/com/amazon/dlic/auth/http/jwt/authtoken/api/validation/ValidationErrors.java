package com.amazon.dlic.auth.http.jwt.authtoken.api.validation;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.json.JsonXContent;

import com.google.common.collect.ImmutableListMultimap;
import com.google.common.collect.LinkedListMultimap;
import com.google.common.collect.Multimap;

public class ValidationErrors implements ToXContent {
    private static final Logger log = LogManager.getLogger(ValidationErrors.class);

    private Multimap<String, ValidationError> attributeToErrorMap;
    private ValidationErrors parent;
    private String attributeInParent;

    public ValidationErrors() {
        this.attributeToErrorMap = LinkedListMultimap.create();
    }

    public ValidationErrors(ValidationErrors parent, String attributeInParent) {
        this.attributeToErrorMap = LinkedListMultimap.create();
        this.parent = parent;
        this.attributeInParent = attributeInParent;
    }

    public ValidationErrors(Multimap<String, ValidationError> multimap) {
        this.attributeToErrorMap = multimap;
    }

    public ValidationErrors(ValidationError singleValidationError) {
        attributeToErrorMap = ImmutableListMultimap.of(singleValidationError.getAttribute(), singleValidationError);
    }

    public void throwExceptionForPresentErrors() throws ConfigValidationException {
        if (hasErrors()) {
            throw new ConfigValidationException(this);
        }
    }

    public boolean hasErrors() {
        return this.attributeToErrorMap.size() > 0;
    }

    public ValidationErrors add(ValidationError validationError) {
        this.attributeToErrorMap.put(validationError.getAttribute(), validationError);

        if (parent != null) {
            parent.add(attributeInParent, new ValidationErrors(validationError));
        }

        return this;
    }

    public ValidationErrors add(String attribute, ValidationErrors validationErrors) {
        for (Map.Entry<String, ValidationError> entry : validationErrors.attributeToErrorMap.entries()) {
            String subAttribute;

            if (attribute != null && !"_".equals(attribute)) {
                if (entry.getKey() != null && !"_".equals(entry.getKey())) {
                    if (entry.getKey().startsWith("[")) {
                        subAttribute = attribute + entry.getKey();
                    } else {
                        subAttribute = attribute + "." + entry.getKey();
                    }

                } else {
                    subAttribute = attribute;
                }
            } else {
                if (entry.getKey() != null && !"_".equals(entry.getKey())) {
                    subAttribute = entry.getKey();
                } else {
                    subAttribute = "_";
                }
            }

            this.attributeToErrorMap.put(subAttribute, entry.getValue());
        }

        if (parent != null) {
            parent.add(attribute == null ? attributeInParent : attribute + "." + attributeInParent, validationErrors);
        }

        return this;
    }

    public ValidationErrors add(String attribute, ConfigValidationException watchValidationException) {
        add(attribute, watchValidationException.getValidationErrors());
        return this;
    }

    public String toJson() {
        try {

            XContentBuilder builder = JsonXContent.contentBuilder();

            this.toXContent(builder, ToXContent.EMPTY_PARAMS);

            return Strings.toString(builder);

        } catch (Exception e) {
            log.error(e.toString(), e);
            throw new RuntimeException(e);
        }
    }

    public String toString() {
        StringBuilder result = new StringBuilder();

        for (Map.Entry<String, ValidationError> entry : this.attributeToErrorMap.entries()) {
            result.append(entry.getKey()).append(":\n\t").append(entry.getValue());
            result.append("\n");
        }

        return result.toString();
    }

    public int size() {
        return this.attributeToErrorMap.size();
    }

    public ValidationError getOnlyValidationError() {
        if (this.attributeToErrorMap.size() == 1) {
            ValidationError result = this.attributeToErrorMap.values().iterator().next();

            // FIXME keep attribute names of errors uptodate

            result.setAttribute(this.attributeToErrorMap.keys().iterator().next());

            return result;
        } else {
            return null;
        }
    }

    public Exception getCause() {
        for (ValidationError validationError : attributeToErrorMap.values()) {
            if (validationError.getCause() != null) {
                return validationError.getCause();
            }
        }

        return null;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();

        for (Map.Entry<String, Collection<ValidationError>> entry : attributeToErrorMap.asMap().entrySet()) {
            builder.field(entry.getKey() != null ? entry.getKey() : "_");

            builder.startArray();

            for (ValidationError validationError : entry.getValue()) {
                builder.value(validationError);
            }

            builder.endArray();
        }

        builder.endObject();

        return builder;
    }
}

