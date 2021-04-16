/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.auditlog.sink;

import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.Settings;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormatter;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditMessage;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.google.common.util.concurrent.Uninterruptibles;

public abstract class AuditLogSink {

    protected final Logger log = LogManager.getLogger(this.getClass());
    protected final Settings settings;
    protected final String settingsPrefix;
    private final String name;
    protected final AuditLogSink fallbackSink;
    private final int retryCount;
    private final long delayMs;

    protected AuditLogSink(String name, Settings settings, String settingsPrefix, AuditLogSink fallbackSink) {
        this.name = name.toLowerCase();
    	this.settings = Objects.requireNonNull(settings);
        this.settingsPrefix = settingsPrefix;
        this.fallbackSink = fallbackSink;

        retryCount = settings.getAsInt(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RETRY_COUNT, 0);
        delayMs = settings.getAsLong(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RETRY_DELAY_MS, 1000L);
    }

    public boolean isHandlingBackpressure() {
        return false;
    }

    public String getName() {
    	return name;
    }

    public AuditLogSink getFallbackSink() {
    	return fallbackSink;
    }

    public final void store(AuditMessage msg) {
		if (!doStoreWithRetry(msg) && !fallbackSink.doStoreWithRetry(msg)) {
			System.err.println(msg.toPrettyString());
		}
    }

    private boolean doStoreWithRetry(AuditMessage msg) {
        //retryCount of 0 means no retry (which is: try exactly once) - delayMs is ignored
        //retryCount of 1 means: try and if this fails wait delayMs and try once again

        if(doStore(msg)) {
            return true;
        }

        final boolean isDebugEnabled = log.isDebugEnabled();
        for(int i=0; i<retryCount; i++) {
            if (isDebugEnabled) {
                log.debug("Retry attempt {}/{} for {} ({})", i+1, retryCount, this.getName(), this.getClass());
            }
            Uninterruptibles.sleepUninterruptibly(delayMs, TimeUnit.MILLISECONDS);
            if(!doStore(msg)) {
                continue;
            } else {
                return true;
            }
        }

        return false;
    }

    protected abstract boolean doStore(AuditMessage msg);

    public void close() throws IOException {
    	// to be implemented by subclasses
    }

    protected String getExpandedIndexName(DateTimeFormatter indexPattern, String index) {
        if(indexPattern == null) {
            return index;
        }
        return indexPattern.print(DateTime.now(DateTimeZone.UTC));
    }

    protected Settings getSinkSettings(String prefix) {
    	return settings.getAsSettings(prefix);
    }

    @Override
    public String toString() {
    	return ("AudtLogSink: Name: " + name+", type: " + this.getClass().getSimpleName());
    }

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		AuditLogSink other = (AuditLogSink) obj;
		if (name == null) {
			if (other.name != null)
				return false;
		} else if (!name.equals(other.name))
			return false;
		return true;
	}


}
