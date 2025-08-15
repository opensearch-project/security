package org.opensearch.sample.scheduledjob;

import java.io.IOException;
import java.time.Instant;

import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.jobscheduler.spi.JobSchedulerExtension;
import org.opensearch.jobscheduler.spi.ScheduledJobParser;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
import org.opensearch.jobscheduler.spi.schedule.ScheduleParser;

public class SampleJobExtension implements JobSchedulerExtension {
    @Override
    public String getJobType() {
        return "sample-secure-job";
    }

    @Override
    public String getJobIndex() {
        return ".sample-secure-job";
    }

    @Override
    public ScheduledJobRunner getJobRunner() {
        return SampleSecureJobRunner.getJobRunnerInstance();
    }

    @Override
    public ScheduledJobParser getJobParser() {
        return (parser, id, jobDocVersion) -> {
            SampleSecureJobParameter jobParameter = new SampleSecureJobParameter();
            XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);

            while (!parser.nextToken().equals(XContentParser.Token.END_OBJECT)) {
                String fieldName = parser.currentName();
                parser.nextToken();
                switch (fieldName) {
                    case SampleSecureJobParameter.NAME_FIELD:
                        jobParameter.setJobName(parser.text());
                        break;
                    case SampleSecureJobParameter.ENABLED_FILED:
                        jobParameter.setEnabled(parser.booleanValue());
                        break;
                    case SampleSecureJobParameter.ENABLED_TIME_FILED:
                        jobParameter.setEnabledTime(parseInstantValue(parser));
                        break;
                    case SampleSecureJobParameter.LAST_UPDATE_TIME_FIELD:
                        jobParameter.setLastUpdateTime(parseInstantValue(parser));
                        break;
                    case SampleSecureJobParameter.SCHEDULE_FIELD:
                        jobParameter.setSchedule(ScheduleParser.parse(parser));
                        break;
                    case SampleSecureJobParameter.INDEX_NAME_FIELD:
                        jobParameter.setIndexToWatch(parser.text());
                        break;
                    case SampleSecureJobParameter.LOCK_DURATION_SECONDS:
                        jobParameter.setLockDurationSeconds(parser.longValue());
                        break;
                    case SampleSecureJobParameter.JITTER:
                        jobParameter.setJitter(parser.doubleValue());
                        break;
                    default:
                        XContentParserUtils.throwUnknownToken(parser.currentToken(), parser.getTokenLocation());
                }
            }
            return jobParameter;
        };
    }

    private Instant parseInstantValue(XContentParser parser) throws IOException {
        if (XContentParser.Token.VALUE_NULL.equals(parser.currentToken())) {
            return null;
        }
        if (parser.currentToken().isValue()) {
            return Instant.ofEpochMilli(parser.longValue());
        }
        XContentParserUtils.throwUnknownToken(parser.currentToken(), parser.getTokenLocation());
        return null;
    }
}
