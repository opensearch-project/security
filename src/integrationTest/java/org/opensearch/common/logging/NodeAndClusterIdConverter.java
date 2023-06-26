/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.common.logging;

/**
* Class uses to override OpenSearch NodeAndClusterIdConverter Log4j2 plugin in order to disable plugin and limit number of
* warn messages like "...ApplierService#updateTask][T#1] WARN ClusterApplierService:628 - failed to notify ClusterStateListener..."
* during tests execution.
*
* The class is rather a temporary solution and the real one should be developed in scope of:
* https://github.com/opensearch-project/OpenSearch/pull/4322
*/
import org.apache.logging.log4j.core.LogEvent;

class NodeAndClusterIdConverter {

    public NodeAndClusterIdConverter() {}

    public static void setNodeIdAndClusterId(String nodeId, String clusterUUID) {}

    public void format(LogEvent event, StringBuilder toAppendTo) {}
}
