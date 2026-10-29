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

package org.opensearch.security.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.logging.DeprecationLogger;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.ReflectionHelper;
import org.opensearch.security.support.SecuritySettings;

/**
 * Selects the {@link InterClusterRequestEvaluator} used to recognise node-to-node transport traffic.
 *
 * <p>{@code plugins.security.cert.intercluster_request_evaluator} ({@code default} or {@code oid}) is the supported way to choose
 * a built-in evaluator. The deprecated {@code plugins.security.cert.intercluster_request_evaluator_class} is still honoured,
 * unless the typed setting is also configured, in which case the typed setting wins.
 * See <a href="https://github.com/opensearch-project/security/issues/6479">#6479</a>.
 */
public final class InterClusterRequestEvaluatorFactory {

    private static final Logger log = LogManager.getLogger(InterClusterRequestEvaluatorFactory.class);
    private static final DeprecationLogger deprecationLogger = DeprecationLogger.getLogger(InterClusterRequestEvaluatorFactory.class);

    // Property.Deprecated already logs under the setting key, and deprecation messages are deduplicated by key, so the migration
    // hint needs its own key to be logged at all
    static final String MIGRATION_DEPRECATION_KEY = "intercluster_request_evaluator_class_migration";

    private InterClusterRequestEvaluatorFactory() {}

    public static InterClusterRequestEvaluator create(final Settings settings) {
        final String legacyClassName = settings.get(ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR_CLASS);
        final boolean legacyConfigured = legacyClassName != null && !legacyClassName.isEmpty();
        final boolean typedConfigured = SecuritySettings.INTERCLUSTER_REQUEST_EVALUATOR.exists(settings);

        if (legacyConfigured) {
            if (typedConfigured) {
                log.warn(
                    "Ignoring deprecated setting [{}] because [{}] is also configured; remove [{}]",
                    ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR_CLASS,
                    ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR,
                    ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR_CLASS
                );
            } else {
                deprecationLogger.deprecate(
                    MIGRATION_DEPRECATION_KEY,
                    "[{}] is deprecated and will be removed in a future major version. {}",
                    ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR_CLASS,
                    migrationHint(legacyClassName)
                );
                return fromClassName(legacyClassName, settings);
            }
        }

        final String type = SecuritySettings.INTERCLUSTER_REQUEST_EVALUATOR.get(settings);
        log.debug("Using [{}] inter-cluster request evaluator", type);
        return ConfigConstants.INTERCLUSTER_REQUEST_EVALUATOR_OID.equals(type)
            ? new OIDClusterRequestEvaluator(settings)
            : new DefaultInterClusterRequestEvaluator(settings);
    }

    private static InterClusterRequestEvaluator fromClassName(final String className, final Settings settings) {
        log.debug("Using {} as inter-cluster request evaluator class", className);
        if (DefaultInterClusterRequestEvaluator.class.getName().equals(className)) {
            return new DefaultInterClusterRequestEvaluator(settings);
        }
        return ReflectionHelper.instantiateInterClusterRequestEvaluator(className, settings);
    }

    private static String migrationHint(final String className) {
        if (DefaultInterClusterRequestEvaluator.class.getName().equals(className)) {
            return "Remove it; the default evaluator is used when nothing is configured.";
        }
        if (OIDClusterRequestEvaluator.class.getName().equals(className)) {
            return "Use [" + ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR + ": oid] instead.";
        }
        return "Custom inter-cluster request evaluators will not be supported after it is removed; use ["
            + ConfigConstants.SECURITY_INTERCLUSTER_REQUEST_EVALUATOR
            + "] with one of "
            + SecuritySettings.INTERCLUSTER_REQUEST_EVALUATOR_VALUES
            + ".";
    }
}
