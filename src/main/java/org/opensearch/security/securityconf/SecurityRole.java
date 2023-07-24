/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

package org.opensearch.security.securityconf;

import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.user.User;

import java.util.Set;

public interface SecurityRole {
    boolean impliesClusterPermission(String action);

    // get indices which are permitted for the given types and actions
    // dnfof + opensearchDashboards special only
    Set<String> getAllResolvedPermittedIndices(
        IndexResolverReplacer.Resolved resolved,
        User user,
        String[] actions,
        IndexNameExpressionResolver resolver,
        ClusterService cs
    );

    @Override
    String toString();

    Set<IndexPattern> getIpatterns();

    String getName();

}
