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
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazon.opendistroforelasticsearch.security.support;

import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;

public class ModuleInfo implements Serializable, Writeable{
	
	private static final long serialVersionUID = -1077651823194285138L;
	
	private ModuleType moduleType;
	private String classname;
	private String classpath = "";
	private String version = "";
	private String buildTime = "";
	private String gitsha1 = "";
	
	public ModuleInfo(ModuleType moduleType, String classname) {
		assert(moduleType != null);
		this.moduleType = moduleType;
		this.classname = classname;
	}

	public ModuleInfo(final StreamInput in) throws IOException {
		moduleType = in.readEnum(ModuleType.class);
		classname = in.readString();
		classpath = in.readString();
		version = in.readString();
		buildTime = in.readString();
		gitsha1 = in.readString();
		assert(moduleType != null);
	}

	public void setClasspath(String classpath) {
		this.classpath = classpath;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public void setBuildTime(String buildTime) {
		this.buildTime = buildTime;
	}
	
	public String getGitsha1() {
        return gitsha1;
    }

    public void setGitsha1(String gitsha1) {
        this.gitsha1 = gitsha1;
    }

    public ModuleType getModuleType() {
		return moduleType;
	}
	
	public Map<String, String> getAsMap() {
		Map<String, String> infoMap = new HashMap<>();
		infoMap.put("type", moduleType.name());
		infoMap.put("description", moduleType.getDescription());
		infoMap.put("is_advanced_module", moduleType.isAdvancedModule().toString());
		infoMap.put("default_implementation", moduleType.getDefaultImplClass());
		infoMap.put("actual_implementation", this.classname);
		//infoMap.put("classpath", this.classpath); //this can disclose file locations
		infoMap.put("version", this.version);
		infoMap.put("buildTime", this.buildTime);
		infoMap.put("gitsha1", this.gitsha1);
		return infoMap;
	}
	
	@Override
	public void writeTo(StreamOutput out) throws IOException {
        out.writeEnum(moduleType);
        out.writeString(classname);
        out.writeString(classpath);
        out.writeString(version);
        out.writeString(buildTime);
        out.writeString(gitsha1);
	}
	
 

	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((buildTime == null) ? 0 : buildTime.hashCode());
		result = prime * result + ((classname == null) ? 0 : classname.hashCode());
		result = prime * result + ((moduleType == null) ? 0 : moduleType.hashCode());
		result = prime * result + ((version == null) ? 0 : version.hashCode());
		result = prime * result + ((gitsha1 == null) ? 0 : gitsha1.hashCode());
		return result;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof ModuleInfo)) {
			return false;
		}
		ModuleInfo other = (ModuleInfo) obj;
		if (buildTime == null) {
			if (other.buildTime != null) {
				return false;
			}
		} else if (!buildTime.equals(other.buildTime)) {
			return false;
		}
		if (classname == null) {
			if (other.classname != null) {
				return false;
			}
		} else if (!classname.equals(other.classname)) {
			return false;
		}
		if (!moduleType.equals(other.moduleType)) {
			return false;
		}
		if (version == null) {
			if (other.version != null) {
				return false;
			}
		} else if (!version.equals(other.version)) {
			return false;
		}
		if (gitsha1 == null) {
            if (other.gitsha1 != null) {
                return false;
            }
        } else if (!gitsha1.equals(other.gitsha1)) {
            return false;
        }
		return true;
	}

	@Override
    public String toString() {
        return "Module [type=" + this.moduleType.name() + ", implementing class=" + this.classname + "]";
    }
    
}
