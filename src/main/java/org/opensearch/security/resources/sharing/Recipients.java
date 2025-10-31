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

    public static Recipients fromXContent(XContentParser parser) throws IOException {
        Map<Recipient, Set<String>> recipients = new HashMap<>();

        XContentParser.Token token;
        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                String fieldName = parser.currentName();
                Recipient recipient = Recipient.valueOf(fieldName.toUpperCase(Locale.ROOT));

                parser.nextToken();
                Set<String> values = new HashSet<>();
                while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                    values.add(parser.text());
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
