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
 * Portions Copyright OpenSearch Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package org.opensearch.security.privileges;

import org.opensearch.action.admin.indices.create.CreateIndexRequestBuilder;
import org.opensearch.security.resolver.IndexResolverReplacer.Resolved;
import org.opensearch.security.securityconf.EvaluatedDlsFlsConfig;

import java.util.HashSet;
import java.util.Set;

public class PrivilegesEvaluatorResponse {
    boolean allowed = false;
    Set<String> missingPrivileges = new HashSet<String>();
    Set<String> missingSecurityRoles = new HashSet<>();
    Set<String> resolvedSecurityRoles = new HashSet<>();
    EvaluatedDlsFlsConfig evaluatedDlsFlsConfig;
    PrivilegesEvaluatorResponseState state = PrivilegesEvaluatorResponseState.PENDING;
    Resolved resolved;
    CreateIndexRequestBuilder createIndexRequestBuilder;
    
    public Resolved getResolved() {
		return resolved;
	}
    
    public boolean isAllowed() {
        return allowed;
    }
    public Set<String> getMissingPrivileges() {
        return new HashSet<String>(missingPrivileges);
    }

    public Set<String> getMissingSecurityRoles() {return new HashSet<>(missingSecurityRoles); }

    public Set<String> getResolvedSecurityRoles() {return new HashSet<>(resolvedSecurityRoles); }

    public EvaluatedDlsFlsConfig getEvaluatedDlsFlsConfig() {
        return evaluatedDlsFlsConfig;
    }
    
    public CreateIndexRequestBuilder getCreateIndexRequestBuilder() {
        return createIndexRequestBuilder;
    }
    
    public PrivilegesEvaluatorResponse markComplete() {
        this.state = PrivilegesEvaluatorResponseState.COMPLETE;
        return this;
    }

    public PrivilegesEvaluatorResponse markPending() {
        this.state = PrivilegesEvaluatorResponseState.PENDING;
        return this;
    }

    public boolean isComplete() {
        return this.state == PrivilegesEvaluatorResponseState.COMPLETE;
    }

    public boolean isPending() {
        return this.state == PrivilegesEvaluatorResponseState.PENDING;
    }

    @Override
    public String toString() {
        return "PrivEvalResponse [allowed=" + allowed + ", missingPrivileges=" + missingPrivileges + ", evaluatedDlsFlsConfig="
                + evaluatedDlsFlsConfig + "]";
    }
    
    public static enum PrivilegesEvaluatorResponseState {
        PENDING,
        COMPLETE;
    }
    
}