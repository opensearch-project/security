/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.privileges.dlsfls;

import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Bounded operator diagnostics; warnings do not change masking or authorization decisions. */
public final class FieldMaskingDiagnostics {
    private static final Logger LOGGER = LogManager.getLogger(FieldMaskingDiagnostics.class);
    private static final FieldMaskingDiagnostics INSTANCE = new FieldMaskingDiagnostics(
        System::nanoTime,
        warning -> LOGGER.warn(
            "Field masking cannot guarantee protection for index [{}], field [{}], type [{}], detected by [{}]. "
                + "Only string values are masked; use FLS to hide unsupported values. Diagnostics are sampled.",
            warning.index(),
            warning.field(),
            warning.type(),
            warning.origin()
        )
    );

    record Warning(String index, String field, String type, String origin) {
    }

    private final Cache<Warning, Boolean> seen = CacheBuilder.newBuilder().maximumSize(1024).expireAfterWrite(10, TimeUnit.MINUTES).build();
    private final LongSupplier clock;
    private final Consumer<Warning> sink;
    private long lastWarning;
    private boolean emitted;

    FieldMaskingDiagnostics(LongSupplier clock, Consumer<Warning> sink) {
        this.clock = clock;
        this.sink = sink;
    }

    public static void warn(String index, String field, String type, String origin) {
        INSTANCE.report(index, field, type, origin);
    }

    synchronized void report(String index, String field, String type, String origin) {
        long now = clock.getAsLong();
        if (emitted && now - lastWarning < TimeUnit.MINUTES.toNanos(1)) {
            return;
        }
        Warning warning = new Warning(safe(index), safe(field), safe(type), safe(origin));
        if (seen.getIfPresent(warning) != null) {
            return;
        }
        // A node-wide limit also bounds output when many distinct fields are encountered.
        seen.put(warning, Boolean.TRUE);
        lastWarning = now;
        emitted = true;
        sink.accept(warning);
    }

    private static String safe(String value) {
        if (value == null) return "unknown";
        return value.substring(0, Math.min(value.length(), 256)).replaceAll("[\\p{Cntrl}]", "?");
    }
}
