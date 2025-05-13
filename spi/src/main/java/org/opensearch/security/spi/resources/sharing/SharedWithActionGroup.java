/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources.sharing;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.opensearch.core.common.io.stream.NamedWriteable;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentFragment;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

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
public class SharedWithActionGroup implements ToXContentFragment, NamedWriteable {

    /*
     * accessLevel is an actionGroup that is pertinent to sharable resources
     *
     * i.e. With Google Docs I can share a doc with another user of Google Docs and specify the access level
     * when sharing
     */
    private final String accessLevel;

    private final AccessLevelRecipients accessLevelRecipients;

    public SharedWithActionGroup(String actionGroup, AccessLevelRecipients accessLevelRecipients) {
        this.accessLevel = actionGroup;
        this.accessLevelRecipients = accessLevelRecipients;
    }

    public SharedWithActionGroup(StreamInput in) throws IOException {
        this.accessLevel = in.readString();
        this.accessLevelRecipients = new AccessLevelRecipients(in);
    }

    public String getAccessLevel() {
        return accessLevel;
    }

    public AccessLevelRecipients getSharedWith() {
        return accessLevelRecipients;
    }

    public void share(SharedWithActionGroup target) {
        Map<Recipient, Set<String>> targetRecipients = target.accessLevelRecipients.getRecipients();
        for (Recipient recipientType : targetRecipients.keySet()) {
            Set<String> recipients = accessLevelRecipients.getRecipientsByType(recipientType);
            recipients.addAll(targetRecipients.get(recipientType));
        }
    }

    public boolean isPublic() {
        return accessLevelRecipients.getRecipients().values().stream().anyMatch(recipients -> recipients.contains("*"));
    }

    public boolean isSharedWithAny(Recipient recipientType, Set<String> targets) {
        return !Collections.disjoint(accessLevelRecipients.getRecipientsByType(recipientType), targets);
    }

    public Set<String> getRecipientsByType(Recipient recipientType) {
        return accessLevelRecipients.getRecipientsByType(recipientType);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.field(accessLevel);
        builder.startObject();

        accessLevelRecipients.toXContent(builder, params);

        return builder.endObject();
    }

    public static SharedWithActionGroup fromXContent(XContentParser parser) throws IOException {
        String actionGroup = parser.currentName();

        parser.nextToken();

        AccessLevelRecipients accessLevelRecipients = AccessLevelRecipients.fromXContent(parser);

        return new SharedWithActionGroup(actionGroup, accessLevelRecipients);
    }

    @Override
    public String toString() {
        return "{" + accessLevel + ": " + accessLevelRecipients + '}';
    }

    @Override
    public String getWriteableName() {
        return "shared_with_access_level";
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(accessLevel);
        out.writeNamedWriteable(accessLevelRecipients);
    }

    /**
     * This class represents the entities with whom a resource is shared with for a given access level.
     *
     * @opensearch.experimental
     */
    public static class AccessLevelRecipients implements ToXContentFragment, NamedWriteable {

        private final Map<Recipient, Set<String>> recipients;

        public AccessLevelRecipients(Map<Recipient, Set<String>> recipients) {
            if (recipients == null) {
                throw new IllegalArgumentException("Recipients map cannot be null");
            }
            this.recipients = recipients;
        }

        public AccessLevelRecipients(StreamInput in) throws IOException {
            this.recipients = in.readMap(key -> key.readEnum(Recipient.class), input -> input.readSet(StreamInput::readString));
        }

        public Map<Recipient, Set<String>> getRecipients() {
            return recipients;
        }

        public Set<String> getRecipientsByType(Recipient recipientType) {
            return recipients.computeIfAbsent(recipientType, key -> new HashSet<>());
        }

        @Override
        public String getWriteableName() {
            return "access_level_recipients";
        }

        public static AccessLevelRecipients fromXContent(XContentParser parser) throws IOException {
            Map<Recipient, Set<String>> recipients = new HashMap<>();

            XContentParser.Token token;
            while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
                if (token == XContentParser.Token.FIELD_NAME) {
                    String fieldName = parser.currentName();
                    Recipient recipient = Recipient.fromValue(fieldName);

                    parser.nextToken();
                    Set<String> values = new HashSet<>();
                    while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                        values.add(parser.text());
                    }
                    recipients.put(recipient, values);
                }
            }

            return new AccessLevelRecipients(recipients);
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeMap(
                recipients,
                StreamOutput::writeEnum,
                (streamOutput, strings) -> streamOutput.writeCollection(strings, StreamOutput::writeString)
            );
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            if (recipients.isEmpty()) {
                return builder;
            }
            for (Map.Entry<Recipient, Set<String>> entry : recipients.entrySet()) {
                builder.array(entry.getKey().getName(), entry.getValue().toArray());
            }
            return builder;
        }
    }
}
