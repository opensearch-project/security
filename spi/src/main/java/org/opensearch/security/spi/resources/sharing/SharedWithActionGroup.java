/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources.sharing;

import java.io.IOException;
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

    private final String actionGroup;

    private final ActionGroupRecipients actionGroupRecipients;

    public SharedWithActionGroup(String actionGroup, ActionGroupRecipients actionGroupRecipients) {
        this.actionGroup = actionGroup;
        this.actionGroupRecipients = actionGroupRecipients;
    }

    public SharedWithActionGroup(StreamInput in) throws IOException {
        this.actionGroup = in.readString();
        this.actionGroupRecipients = new ActionGroupRecipients(in);
    }

    public String getActionGroup() {
        return actionGroup;
    }

    public ActionGroupRecipients getSharedWithPerActionGroup() {
        return actionGroupRecipients;
    }

    public void share(SharedWithActionGroup target) {
        Map<Recipient, Set<String>> targetRecipients = target.actionGroupRecipients.getRecipients();
        for (Recipient recipientType : targetRecipients.keySet()) {
            Set<String> recipients = actionGroupRecipients.getRecipientsByType(recipientType);
            recipients.addAll(targetRecipients.get(recipientType));
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.field(actionGroup);
        builder.startObject();

        actionGroupRecipients.toXContent(builder, params);

        return builder.endObject();
    }

    public static SharedWithActionGroup fromXContent(XContentParser parser) throws IOException {
        String actionGroup = parser.currentName();

        parser.nextToken();

        ActionGroupRecipients actionGroupRecipients = ActionGroupRecipients.fromXContent(parser);

        return new SharedWithActionGroup(actionGroup, actionGroupRecipients);
    }

    @Override
    public String toString() {
        return "{" + actionGroup + ": " + actionGroupRecipients + '}';
    }

    @Override
    public String getWriteableName() {
        return "shared_with_action_group";
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(actionGroup);
        out.writeNamedWriteable(actionGroupRecipients);
    }

    /**
     * This class represents the entities with whom a resource is shared with for a given action-group.
     *
     * @opensearch.experimental
     */
    public static class ActionGroupRecipients implements ToXContentFragment, NamedWriteable {

        private final Map<Recipient, Set<String>> recipients;

        public ActionGroupRecipients(Map<Recipient, Set<String>> recipients) {
            if (recipients == null) {
                throw new IllegalArgumentException("Recipients map cannot be null");
            }
            this.recipients = recipients;
        }

        public ActionGroupRecipients(StreamInput in) throws IOException {
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
            return "action_group_recipients";
        }

        public static ActionGroupRecipients fromXContent(XContentParser parser) throws IOException {
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

            return new ActionGroupRecipients(recipients);
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
