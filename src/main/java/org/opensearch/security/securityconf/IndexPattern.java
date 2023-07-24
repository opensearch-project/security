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
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;

import java.util.List;
import java.util.Set;

public interface IndexPattern {
    IndexPattern addFlsFields(List<String> flsFields);

    IndexPattern addMaskedFields(List<String> maskedFields);

    WildcardMatcher getPerms();

    Set<String> getStringPerm();

    WildcardMatcher getNonWildCardPerms();

    String getDlsQuery(User user);

    Set<String> concreteIndexNames(User user, IndexNameExpressionResolver resolver, ClusterService cs);

    Set<String> getFls();

    Set<String> getMaskedFields();

    boolean hasDlsQuery();

    boolean hasFlsFields();

    boolean hasMaskedFields();

    String getUnresolvedIndexPattern(User user);

    Set<String> attemptResolveIndexNames(User user, IndexNameExpressionResolver resolver, ClusterService cs);

    Set<String> getResolvedIndexPattern(User user, IndexNameExpressionResolver resolver, ClusterService cs);

    Set<TypePerm> getTypePerms();
}
