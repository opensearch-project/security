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

package org.opensearch.security.identity;
import java.io.IOException;
import java.time.Instant;

import com.google.common.base.Objects;

import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.core.ParseField;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.security.user.User;

import static org.opensearch.common.xcontent.XContentParserUtils.ensureExpectedToken;

/**
 * Scheduled Job Identity.
 */
public class ScheduledJobIdentity implements Writeable, ToXContentObject {
    public static final String JOB_ID_FIELD = "job_id";
    public static final String JOB_INDEX_FIELD = "job_index";
    public static final String LAST_UPDATE_TIME_FIELD = "last_update_time";
    public static final String CREATED_TIME_FIELD = "created_time";
    public static final String USER_FIELD = "user";

    private final String jobId;
    private final String jobIndex;
    private final Instant createdTime;
    private final Instant lastUpdateTime;
    private final User user;

    public ScheduledJobIdentity(
            String jobId,
            String jobIndex,
            Instant createdTime,
            Instant lastUpdateTime,
            User user
    ) {
        this.jobId = jobId;
        this.jobIndex = jobIndex;
        this.createdTime = createdTime;
        this.lastUpdateTime = lastUpdateTime;
        this.user = user;
    }

    public ScheduledJobIdentity(StreamInput input) throws IOException {
        jobId = input.readString();
        jobIndex = input.readString();
        createdTime = input.readInstant();
        lastUpdateTime = input.readInstant();
        if (input.readBoolean()) {
            user = new User(input);
        } else {
            user = null;
        }
    }

    /**
     * Parse content parser to {@link java.time.Instant}.
     *
     * @param parser json based content parser
     * @return instance of {@link java.time.Instant}
     * @throws IOException IOException if content can't be parsed correctly
     */
    public static Instant toInstant(XContentParser parser) throws IOException {
        if (parser.currentToken() == null || parser.currentToken() == XContentParser.Token.VALUE_NULL) {
            return null;
        }
        if (parser.currentToken().isValue()) {
            return Instant.ofEpochMilli(parser.longValue());
        }
        return null;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        XContentBuilder xContentBuilder = builder
                .startObject()
                .field(JOB_ID_FIELD, jobId)
                .field(JOB_INDEX_FIELD, jobIndex)
                .field(CREATED_TIME_FIELD, createdTime.toEpochMilli())
                .field(LAST_UPDATE_TIME_FIELD, lastUpdateTime.toEpochMilli());
        if (user != null) {
            xContentBuilder.field(USER_FIELD, user);
        }
        return xContentBuilder.endObject();
    }

    @Override
    public void writeTo(StreamOutput output) throws IOException {
        output.writeString(jobId);
        output.writeString(jobIndex);
        output.writeInstant(createdTime);
        output.writeInstant(lastUpdateTime);
        if (user != null) {
            output.writeBoolean(true); // user exists
            user.writeTo(output);
        } else {
            output.writeBoolean(false); // user does not exist
        }
    }

    public static ScheduledJobIdentity parse(XContentParser parser) throws IOException {
        String jobId = null;
        String jobIndex = null;
        Instant createdTime = null;
        Instant lastUpdateTime = null;
        User user = null;

        ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.currentToken(), parser);
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = parser.currentName();
            parser.nextToken();

            switch (fieldName) {
                case JOB_ID_FIELD:
                    jobId = parser.text();
                    break;
                case JOB_INDEX_FIELD:
                    jobIndex = parser.text();
                    break;
                case CREATED_TIME_FIELD:
                    createdTime = toInstant(parser);
                    break;
                case LAST_UPDATE_TIME_FIELD:
                    lastUpdateTime = toInstant(parser);
                    break;
                case USER_FIELD:
                    user = User.parse(parser);
                    break;
                default:
                    parser.skipChildren();
                    break;
            }
        }
        return new ScheduledJobIdentity(
                jobId,
                jobIndex,
                createdTime,
                lastUpdateTime,
                user
        );
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        ScheduledJobIdentity that = (ScheduledJobIdentity) o;
        return Objects.equal(getJobId(), that.getJobId())
                && Objects.equal(getJobIndex(), that.getJobIndex())
                && Objects.equal(getCreatedTime(), that.getCreatedTime())
                && Objects.equal(getLastUpdateTime(), that.getLastUpdateTime());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(jobId, jobIndex, createdTime, lastUpdateTime);
    }

    public String getJobId() {
        return jobId;
    }
    public String getJobIndex() {
        return jobIndex;
    }
    public Instant getCreatedTime() {
        return createdTime;
    }

    public Instant getLastUpdateTime() {
        return lastUpdateTime;
    }

    public User getUser() {
        return user;
    }
}