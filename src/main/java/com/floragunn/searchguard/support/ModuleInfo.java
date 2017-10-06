package com.floragunn.searchguard.support;

import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;

public class ModuleInfo implements Serializable, Writeable{
	
	private static final long serialVersionUID = -1077651823194285138L;
	
	private ModuleType moduleType;
	private String classname;
	private String classpath;
	private String version;
	private String buildTime;
	
	public ModuleInfo(ModuleType moduleType, String classname) {
		this.moduleType = moduleType;
		this.classname = classname;
	}

	public ModuleInfo(final StreamInput in) throws IOException {
		moduleType = in.readEnum(ModuleType.class);
		classname = in.readString();
		classpath = in.readString();
		version = in.readString();
		buildTime = in.readString();
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
	
	public ModuleType getModuleType() {
		return moduleType;
	}
	
	public Map<String, String> getAsMap() {
		Map<String, String> infoMap = new HashMap<>();
		infoMap.put("type", moduleType.name());
		infoMap.put("description", moduleType.getDescription());
		infoMap.put("is_enterprise", moduleType.isEnterprise().toString());
		infoMap.put("default implementation", moduleType.getDefaultImplClass());
		infoMap.put("actual implementation", this.classname);
		infoMap.put("classpath", this.classpath);
		infoMap.put("version", this.version);
		infoMap.put("buildTime", this.buildTime);
		return infoMap;
	}
	
	@Override
	public void writeTo(StreamOutput out) throws IOException {
        out.writeEnum(moduleType);
        out.writeString(classname);
        out.writeString(classpath);
        out.writeString(version);
        out.writeString(buildTime);
	}
	
    @Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((buildTime == null) ? 0 : buildTime.hashCode());
		result = prime * result + ((classname == null) ? 0 : classname.hashCode());
		result = prime * result + ((classpath == null) ? 0 : classpath.hashCode());
		result = prime * result + ((moduleType == null) ? 0 : moduleType.hashCode());
		result = prime * result + ((version == null) ? 0 : version.hashCode());
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
		ModuleInfo other = (ModuleInfo) obj;
		if (buildTime == null) {
			if (other.buildTime != null)
				return false;
		} else if (!buildTime.equals(other.buildTime))
			return false;
		if (classname == null) {
			if (other.classname != null)
				return false;
		} else if (!classname.equals(other.classname))
			return false;
		if (classpath == null) {
			if (other.classpath != null)
				return false;
		} else if (!classpath.equals(other.classpath))
			return false;
		if (moduleType != other.moduleType)
			return false;
		if (version == null) {
			if (other.version != null)
				return false;
		} else if (!version.equals(other.version))
			return false;
		return true;
	}

	@Override
    public String toString() {
        return "Module [type=" + this.moduleType.name() + ", implementing class=" + this.classname + "]";
    }
    
}
