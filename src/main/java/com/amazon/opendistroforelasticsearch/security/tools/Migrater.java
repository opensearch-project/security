/*
 * Copyright 2015-2017 floragunn GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.amazon.opendistroforelasticsearch.security.tools;

import java.io.File;

import com.amazon.opendistroforelasticsearch.security.securityconf.impl.NodesDn;
import com.amazon.opendistroforelasticsearch.security.support.ConfigHelper;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.elasticsearch.common.collect.Tuple;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.securityconf.Migration;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.RoleV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.TenantV7;
import com.google.common.io.Files;

public class Migrater {

    public static void main(final String[] args) {

        final Options options = new Options();
        final HelpFormatter formatter = new HelpFormatter();
        options.addOption(Option.builder("dir").argName("directory").hasArg().required().desc("Directory containing file to be migrated").build());

        final CommandLineParser parser = new DefaultParser();
        try {
            final CommandLine line = parser.parse(options, args);
            
            if(line.hasOption("dir")) {
                final File dir = new File(line.getOptionValue("dir"));
                if(!migrateDirectory(dir, true)) {
                    System.exit(-1);
                } else {
                    System.exit(0);
                }
            }
        } catch (final Exception exp) {
            System.err.println("Parsing failed.  Reason: " + exp.getMessage());
            formatter.printHelp("migrater.sh", options, true);
        }
        
        System.exit(-1);
    }
    
    public static boolean migrateDirectory(File dir, boolean backup) {
        if(!dir.exists()) {
            System.out.println(dir.getAbsolutePath()+" does not exist");
            return false;
        }
        
        if(!dir.isDirectory()) {
            System.out.println(dir.getAbsolutePath()+" is not a directory");
            return false;
        }
        
        boolean retVal = migrateFile(new File(dir, "config.yml"), CType.CONFIG, backup);
        retVal = migrateFile(new File(dir, "action_groups.yml"), CType.ACTIONGROUPS, backup)  && retVal;
        retVal = migrateFile(new File(dir, "roles.yml"), CType.ROLES, backup)  && retVal;
        retVal = migrateFile(new File(dir, "roles_mapping.yml"), CType.ROLESMAPPING, backup)  && retVal;
        retVal = migrateFile(new File(dir, "internal_users.yml"), CType.INTERNALUSERS, backup)  && retVal;
        retVal = migrateFile(new File(dir, "nodes_dn.yml"), CType.NODESDN, backup)  && retVal;
        retVal = migrateFile(new File(dir, "audit.yml"), CType.AUDIT, backup)  && retVal;

        return retVal;
    }

    public static boolean migrateFile(File file, CType cType, boolean backup) {
        final String absolutePath = file.getAbsolutePath();
        // NODESDN is newer type and supports populating empty content if file is missing
        if(!file.exists() && cType != CType.NODESDN) {
            System.out.println("Skip "+absolutePath+" because it does not exist");
            return false;
        }
        
        if(!file.isFile()) {
            System.out.println("Skip "+absolutePath+" because it is a directory or a special file");
            return false;
        }

        try {
            if(cType == CType.ACTIONGROUPS) {
                SecurityDynamicConfiguration<?> val;
                try {
                    val = Migration.migrateActionGroups(SecurityDynamicConfiguration.fromNode(DefaultObjectMapper.YAML_MAPPER.readTree(file), CType.ACTIONGROUPS, 0, 0, 0));
                } catch (Exception e) {
                    val = Migration.migrateActionGroups(SecurityDynamicConfiguration.fromNode(DefaultObjectMapper.YAML_MAPPER.readTree(file), CType.ACTIONGROUPS, 1, 0, 0));
                }
                return backupAndWrite(file, val, backup);
            }
            
            if(cType == CType.CONFIG) {
                SecurityDynamicConfiguration<?> val = Migration.migrateConfig(SecurityDynamicConfiguration.fromNode(DefaultObjectMapper.YAML_MAPPER.readTree(file), CType.CONFIG, 1, 0, 0));
                return backupAndWrite(file, val, backup);
            }

            if(cType == CType.ROLES) {
                Tuple<SecurityDynamicConfiguration<RoleV7>, SecurityDynamicConfiguration<TenantV7>> tup = Migration.migrateRoles(SecurityDynamicConfiguration.fromNode(DefaultObjectMapper.YAML_MAPPER.readTree(file), CType.ROLES, 1, 0, 0), null);
                boolean roles = backupAndWrite(file, tup.v1(), backup);
                return roles && backupAndWrite(new File(file.getParent(),"tenants.yml"), tup.v2(), backup);
            }
            
            if(cType == CType.ROLESMAPPING) {
                SecurityDynamicConfiguration<?> val = Migration.migrateRoleMappings(SecurityDynamicConfiguration.fromNode(DefaultObjectMapper.YAML_MAPPER.readTree(file), CType.ROLESMAPPING, 1, 0, 0));
                return backupAndWrite(file, val, backup);
            }
            
            if(cType == CType.INTERNALUSERS) {
                SecurityDynamicConfiguration<?> val = Migration.migrateInternalUsers(SecurityDynamicConfiguration.fromNode(DefaultObjectMapper.YAML_MAPPER.readTree(file), CType.INTERNALUSERS, 1, 0, 0));
                return backupAndWrite(file, val, backup);
            }

            if(cType == CType.AUDIT) {
                SecurityDynamicConfiguration<?> val = Migration.migrateAudit(SecurityDynamicConfiguration.fromNode(DefaultObjectMapper.YAML_MAPPER.readTree(file), CType.AUDIT, 1, 0, 0));
                return backupAndWrite(file, val, backup);
            }

            if(cType == CType.NODESDN) {
                SecurityDynamicConfiguration<NodesDn> val =
                    Migration.migrateNodesDn(SecurityDynamicConfiguration.fromNode(
                        DefaultObjectMapper.YAML_MAPPER.readTree(ConfigHelper.createFileOrStringReader(CType.NODESDN, 1, file.getAbsolutePath(), true)),
                        CType.NODESDN, 1, 0, 0));
                return backupAndWrite(file, val, backup);
            }
        } catch (Exception e) {
            System.out.println("Can not migrate "+file+" due to "+e);
        }
        
        
        return false;
    }
    
    private static boolean backupAndWrite(File file, SecurityDynamicConfiguration<?> val, boolean backup) {
        try {
            if(val == null) {
                System.out.println("NULL object for "+file.getAbsolutePath());
                return false;
            }
            if(backup && file.exists()) {
                Files.copy(file, new File(file.getParent(), file.getName()+".bck6"));
            }
            DefaultObjectMapper.YAML_MAPPER.writeValue(file, val);
            System.out.println("Migrated (as "+val.getCType()+") "+file.getAbsolutePath());
            return true;
        } catch (Exception e) {
            System.out.println("Unable to write "+file.getAbsolutePath()+". This is unexpected and we will abort migration.");
            System.out.println("    Details: "+e.getMessage());
            e.printStackTrace();
        }
        
        return false;
    }
}
