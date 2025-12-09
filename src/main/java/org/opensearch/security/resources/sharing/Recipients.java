/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.sharing;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.opensearch.core.common.io.stream.NamedWriteable;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentFragment;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;

/**
 * This class represents the entities with which a resource is shared for a particular action-group.
 * Example:
 * "default": {
 * "users": [],
 * "roles": [],
 * "backend_roles": []
 * }
 * where "users", "roles" and "backend_roles" are the recipient entities, and "default" is the action-group
 *
 * @opensearch.experimental
 */
public class Recipients implements ToXContentFragment, NamedWriteable {

    /*
     * accessLevel is an actionGroup that is pertinent to sharable resources
     *
     * i.e. With Google Docs I can share a doc with another user of Google Docs and specify the access level
     * when sharing
     */
    private final Map<Recipient, Set<String>> recipients;

    public Recipients(Map<Recipient, Set<String>> recipients) {
        this.recipients = recipients;
    }

    public Recipients(StreamInput in) throws IOException {
        this.recipients = in.readMap(key -> key.readEnum(Recipient.class), input -> input.readSet(StreamInput::readString));
    }

    public Map<Recipient, Set<String>> getRecipients() {
        return recipients;
    }

    public void share(Recipients target) {
        Map<Recipient, Set<String>> targetRecipients = target.getRecipients();
        for (Recipient recipientType : targetRecipients.keySet()) {
            recipients.computeIfAbsent(recipientType, k -> new HashSet<>())
                .addAll(targetRecipients.getOrDefault(recipientType, Collections.emptySet()));
        }
    }

    public void revoke(Recipients target) {
        Map<Recipient, Set<String>> targetRecipients = target.getRecipients();
        for (Recipient recipientType : targetRecipients.keySet()) {
            recipients.computeIfPresent(recipientType, (k, s) -> {
                s.removeAll(targetRecipients.getOrDefault(recipientType, Collections.emptySet()));
                return s;
            });
        }
    }

    public boolean isPublic() {
        return recipients.values().stream().anyMatch(recipients -> recipients.contains("*"));
    }

    public boolean isSharedWithAny(Recipient recipientType, Set<String> targets) {
        return !Collections.disjoint(recipients.getOrDefault(recipientType, Collections.emptySet()), targets);
    }

    public Set<String> getRecipientsByType(Recipient recipientType) {
        return recipients.get(recipientType);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        for (Map.Entry<Recipient, Set<String>> entry : recipients.entrySet()) {
            builder.array(entry.getKey().getName(), entry.getValue().toArray());
        }
        return builder.endObject();
    }

    /**
     * Parse Recipients from XContent with validators
     * @param parser the XContent parser
     * @param arraySizeValidator optional validator for array size (can be null)
     * @param elementValidator optional validator for each array element value (can be null)
     */
    public static Recipients fromXContent(
        XContentParser parser,
        RequestContentValidator.FieldValidator arraySizeValidator,
        RequestContentValidator.FieldValidator elementValidator
    ) throws IOException {
        Map<Recipient, Set<String>> recipients = new HashMap<>();

        XContentParser.Token token;
        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                String fieldName = parser.currentName();

                final Recipient recipient;
                try {
                    recipient = Recipient.valueOf(fieldName.toUpperCase(Locale.ROOT));
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("Unknown recipient type [" + fieldName + "]", e);
                }

                parser.nextToken();
                if (parser.currentToken() != XContentParser.Token.START_ARRAY) {
                    throw new IllegalArgumentException("Expected array for [" + fieldName + "], but found [" + parser.currentToken() + "]");
                }

                Set<String> values = new HashSet<>();
                int count = 0;

                while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                    count++;

                    // Validate array size if validator provided
                    if (arraySizeValidator != null) {
                        arraySizeValidator.validate(fieldName, count);
                    }

                    String value = parser.text();

                    // Validate element value if validator provided
                    // For "users" field, allow wildcard; for others, don't
                    if (elementValidator != null) {
                        // Check if wildcard should be allowed based on recipient type
                        boolean allowWildcard = (recipient == Recipient.USERS);
                        if (allowWildcard) {
                            // Use wildcard-enabled validator for users
                            RequestContentValidator.PRINCIPAL_VALIDATOR_WITH_WILDCARD.validate(fieldName, value);
                        } else {
                            // Use standard validator for roles and backend_roles
                            elementValidator.validate(fieldName, value);
                        }
                    }

                    values.add(value);
                }
                recipients.put(recipient, values);
            }
        }

        return new Recipients(recipients);
    }

    @Override
    public String toString() {
        return recipients.toString();
    }

    @Override
    public String getWriteableName() {
        return "access_level_recipients";
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeMap(
            recipients,
            StreamOutput::writeEnum,
            (streamOutput, strings) -> streamOutput.writeCollection(strings, StreamOutput::writeString)
        );
    }
}
