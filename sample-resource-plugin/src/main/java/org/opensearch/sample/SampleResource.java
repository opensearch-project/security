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

package org.opensearch.sample;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.opensearch.commons.authuser.User;
import org.opensearch.core.ParseField;
import org.opensearch.core.common.io.stream.NamedWriteable;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ConstructingObjectParser;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import static org.opensearch.core.xcontent.ConstructingObjectParser.constructorArg;
import static org.opensearch.core.xcontent.ConstructingObjectParser.optionalConstructorArg;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;

/**
 * Sample resource declared by this plugin.
 */
public class SampleResource implements NamedWriteable, ToXContentObject {

    private String name;
    private String description;
    private String groupId;
    private Map<String, String> attributes;
    // NOTE: following field is added to specifically test migrate API, for newer resources this field must not be defined
    private User user;
    // Workspace membership; optional, models the multi-valued "workspaces" field a real workspace-aware resource
    // would declare so ResourceIndexListener can project workspace:<id> into all_shared_principals.
    private Set<String> workspaces;

    public SampleResource() throws IOException {
        super();
    }

    public SampleResource(StreamInput in) throws IOException {
        this.name = in.readString();
        this.description = in.readOptionalString();
        this.groupId = in.readOptionalString();
        this.attributes = in.readMap(StreamInput::readString, StreamInput::readString);
        this.user = new User(in);
        List<String> ws = in.readOptionalStringList();
        this.workspaces = ws == null ? null : new HashSet<>(ws);
    }

    private static final ConstructingObjectParser<SampleResource, Void> PARSER = new ConstructingObjectParser<>(RESOURCE_TYPE, true, a -> {
        SampleResource s;
        try {
            s = new SampleResource();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        s.setName((String) a[0]);
        s.setDescription((String) a[1]);
        // Used for parentId testing for resource hierarchy
        s.setGroupId((String) a[2]);
        // ignore a[3] as we know the type
        s.setAttributes((Map<String, String>) a[4]);
        s.setUser((User) a[5]);
        List<String> ws = (List<String>) a[6];
        if (ws != null) {
            s.setWorkspaces(new HashSet<>(ws));
        }
        return s;
    });

    static {
        PARSER.declareString(constructorArg(), new ParseField("name"));
        PARSER.declareStringOrNull(optionalConstructorArg(), new ParseField("description"));
        PARSER.declareStringOrNull(optionalConstructorArg(), new ParseField("group_id"));
        PARSER.declareStringOrNull(optionalConstructorArg(), new ParseField("resource_type"));
        PARSER.declareObjectOrNull(optionalConstructorArg(), (p, c) -> p.mapStrings(), null, new ParseField("attributes"));
        PARSER.declareObjectOrNull(optionalConstructorArg(), (p, c) -> User.parse(p), null, new ParseField("user"));
        PARSER.declareStringArray(optionalConstructorArg(), new ParseField("workspaces"));
    }

    public static SampleResource fromXContent(XContentParser parser) throws IOException {
        return PARSER.parse(parser, null);
    }

    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params) throws IOException {
        builder.startObject()
            .field("name", name)
            .field("description", description)
            .field("group_id", groupId)
            .field("resource_type", RESOURCE_TYPE)
            .field("attributes", attributes)
            .field("user", user);
        // Emit workspaces only when non-empty so pre-existing docs stay byte-identical (BWC for callers/tests
        // that don't touch this field).
        if (workspaces != null && !workspaces.isEmpty()) {
            builder.field("workspaces", workspaces);
        }
        return builder.endObject();
    }

    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(name);
        out.writeOptionalString(description);
        out.writeOptionalString(groupId);
        out.writeMap(attributes, StreamOutput::writeString, StreamOutput::writeString);
        user.writeTo(out);
        // Symmetric with the StreamInput ctor. Passing null when unset keeps mixed-caller compatibility.
        out.writeOptionalStringCollection(workspaces);
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public void setGroupId(String groupId) {
        this.groupId = groupId;
    }

    public void setAttributes(Map<String, String> attributes) {
        this.attributes = attributes;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public void setWorkspaces(Set<String> workspaces) {
        this.workspaces = workspaces;
    }

    public Set<String> getWorkspaces() {
        return workspaces;
    }

    public String getName() {
        return name;
    }

    @Override
    public String getWriteableName() {
        return RESOURCE_TYPE;
    }
}
