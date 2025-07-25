/*
 * Copyright 2016 Scott Weeden and/or his affiliates
 * and other contributors as indicated by the @author tags.
 *
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
package org.keycloak.client.admin.cli.commands;

import org.keycloak.client.admin.cli.operations.ClientOperations;
import org.keycloak.client.admin.cli.operations.GroupOperations;
import org.keycloak.client.admin.cli.operations.RoleOperations;
import org.keycloak.client.admin.cli.operations.UserOperations;
import org.keycloak.client.cli.config.ConfigData;

import java.io.PrintWriter;
import java.io.StringWriter;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import static org.keycloak.client.admin.cli.KcAdmMain.CMD;
import static org.keycloak.client.cli.util.ConfigUtil.credentialsAvailable;
import static org.keycloak.client.cli.util.ConfigUtil.loadConfig;
import static org.keycloak.client.cli.util.HttpUtil.composeResourceUrl;
import static org.keycloak.client.cli.util.OsUtil.PROMPT;

/**
 * @author <a href="mailto:mstrukel@redhat.com">Marko Strukelj</a>
 */
@Command(name = "get-roles", description = "[ARGUMENTS]")
public class GetRolesCmd extends GetCmd {

    @Option(names = "--uusername", description = "Target user's 'username'")
    String uusername;

    @Option(names = "--uid", description = "Target user's 'id'")
    String uid;

    @Option(names = "--cclientid", description = "Target client's 'clientId'")
    String cclientid;

    @Option(names = "--cid", description = "Target client's 'id'")
    String cid;

    @Option(names = "--rname", description = "Composite role's 'name'")
    String rname;

    @Option(names = "--rid", description = "Composite role's 'id'")
    String rid;

    @Option(names = "--gname", description = "Target group's 'name'")
    String gname;

    @Option(names = "--gpath", description = "Target group's 'path'")
    String gpath;

    @Option(names = "--gid", description = "Target group's 'id'")
    String gid;

    @Option(names = "--rolename", description = "Target role's 'name'")
    String rolename;

    @Option(names = "--roleid", description = "Target role's 'id'")
    String roleid;

    @Option(names = "--available", description = "List only available roles")
    boolean available;

    @Option(names = "--effective", description = "List assigned roles including transitively included roles")
    boolean effective;

    @Option(names = "--all", description = "List roles for all clients in addition to realm roles")
    boolean all;

    @Override
    protected void processOptions() {
        // hack args so that GetCmd option check doesn't fail
        // set a placeholder
        if (uri == null) {
            uri = "uri";
        }

        if (uid != null && uusername != null) {
            throw new IllegalArgumentException("Incompatible options: --uid and --uusername are mutually exclusive");
        }

        if ((gid != null && gname != null) || (gid != null && gpath != null) || (gname != null && gpath != null)) {
            throw new IllegalArgumentException("Incompatible options: --gid, --gname and --gpath are mutually exclusive");
        }

        if (roleid != null && rolename != null) {
            throw new IllegalArgumentException("Incompatible options: --roleid and --rolename are mutually exclusive");
        }

        if (rid != null && rname != null) {
            throw new IllegalArgumentException("Incompatible options: --rid and --rname are mutually exclusive");
        }

        if (cid != null && cclientid != null) {
            throw new IllegalArgumentException("Incompatible options: --cid and --cclientid are mutually exclusive");
        }

        if (isUserSpecified() && isGroupSpecified()) {
            throw new IllegalArgumentException("Incompatible options: --uusername / --uid can't be used at the same time as --gname / --gid / --gpath");
        }

        if (isUserSpecified() && isCompositeRoleSpecified()) {
            throw new IllegalArgumentException("Incompatible options: --uusername / --uid can't be used at the same time as --rname / --rid");
        }

        if (isGroupSpecified() && isCompositeRoleSpecified()) {
            throw new IllegalArgumentException("Incompatible options: --rname / --rid can't be used at the same time as --gname / --gid / --gpath");
        }

        if (all && effective) {
            throw new IllegalArgumentException("Incompatible options: --all can't be used at the same time as --effective");
        }

        if (all && available) {
            throw new IllegalArgumentException("Incompatible options: --all can't be used at the same time as --available");
        }

        super.processOptions();
    }

    @Override
    protected void process() {
        ConfigData config = loadConfig();
        config = copyWithServerInfo(config);

        setupTruststore(config);

        String auth = null;

        config = ensureAuthInfo(config);
        config = copyWithServerInfo(config);
        if (credentialsAvailable(config)) {
            auth = ensureToken(config);
        }

        auth = auth != null ? "Bearer " + auth : null;

        final String server = config.getServerUrl();
        final String realm = getTargetRealm(config);
        final String adminRoot = adminRestRoot != null ? adminRestRoot : composeAdminRoot(server);

        if (isUserSpecified()) {
            if (uid == null) {
                uid = UserOperations.getIdFromUsername(adminRoot, realm, auth, uusername);
            }
            if (isClientSpecified()) {
                // list client roles for a user
                if (cid == null) {
                    cid = ClientOperations.getIdFromClientId(adminRoot, realm, auth, cclientid);
                }
                if (available) {
                    super.uri = composeResourceUrl(adminRoot, realm, "users/" + uid + "/role-mappings/clients/" + cid + "/available");
                } else if (effective) {
                    super.uri = composeResourceUrl(adminRoot, realm, "users/" + uid + "/role-mappings/clients/" + cid + "/composite");
                } else {
                    super.uri = composeResourceUrl(adminRoot, realm, "users/" + uid + "/role-mappings/clients/" + cid);
                }
            } else {
                // list realm roles for a user
                if (available) {
                    super.uri = composeResourceUrl(adminRoot, realm, "users/" + uid + "/role-mappings/realm/available");
                } else if (effective) {
                    super.uri = composeResourceUrl(adminRoot, realm, "users/" + uid + "/role-mappings/realm/composite");
                } else {
                    super.uri = composeResourceUrl(adminRoot, realm, "users/" + uid + (all ? "/role-mappings" : "/role-mappings/realm"));
                }
            }
        } else if (isGroupSpecified()) {
            if (gname != null) {
                gid = GroupOperations.getIdFromName(adminRoot, realm, auth, gname);
            } else if (gpath != null) {
                gid = GroupOperations.getIdFromPath(adminRoot, realm, auth, gpath);
            }
            if (isClientSpecified()) {
                // list client roles for a group
                if (cid == null) {
                    cid = ClientOperations.getIdFromClientId(adminRoot, realm, auth, cclientid);
                }
                if (available) {
                    super.uri = composeResourceUrl(adminRoot, realm, "groups/" + gid + "/role-mappings/clients/" + cid + "/available");
                } else if (effective) {
                    super.uri = composeResourceUrl(adminRoot, realm, "groups/" + gid + "/role-mappings/clients/" + cid + "/composite");
                } else {
                    super.uri = composeResourceUrl(adminRoot, realm, "groups/" + gid + "/role-mappings/clients/" + cid);
                }
            } else {
                // list realm roles for a group
                if (available) {
                    super.uri = composeResourceUrl(adminRoot, realm, "groups/" + gid + "/role-mappings/realm/available");
                } else if (effective) {
                    super.uri = composeResourceUrl(adminRoot, realm, "groups/" + gid + "/role-mappings/realm/composite");
                } else {
                    super.uri = composeResourceUrl(adminRoot, realm, "groups/" + gid + (all ? "/role-mappings" : "/role-mappings/realm"));
                }
            }
        } else if (isCompositeRoleSpecified()) {
            String uri = rname != null ? "roles/" + rname : "roles-by-id/" + rid;

            if (isClientSpecified()) {
                if (cid == null) {
                    cid = ClientOperations.getIdFromClientId(adminRoot, realm, auth, cclientid);
                }
                if (available) {
                    throw new IllegalArgumentException("Option --available not supported with composite roles. Try '" + CMD + " get-roles --cid " + cid + "' for full list of client roles for that client");
                }
                if (effective) {
                    throw new IllegalArgumentException("Option --effective not supported with composite roles.");
                }
                uri += "/composites/clients/" + cid;
            } else {
                if (available) {
                    throw new IllegalArgumentException("Option --available not supported with composite roles. Try '" + CMD + " get-roles' for full list of realm roles");
                }
                if (effective) {
                    throw new IllegalArgumentException("Option --effective not supported with composite roles.");
                }

                uri += all ? "/composites" : "/composites/realm";
            }
            super.uri = composeResourceUrl(adminRoot, realm, uri);

        } else if (isClientSpecified()) {
            if (cid == null) {
                cid = ClientOperations.getIdFromClientId(adminRoot, realm, auth, cclientid);
            }

            if (isRoleSpecified()) {
                // get specific client role
                if (rolename == null) {
                    rolename = RoleOperations.getClientRoleNameFromId(adminRoot, realm, auth, cid, roleid);
                }
                super.uri = composeResourceUrl(adminRoot, realm, "clients/" + cid + "/roles/" + rolename);
            } else {
                // list defined client roles
                super.uri = composeResourceUrl(adminRoot, realm, "clients/" + cid + "/roles");
            }
        } else {
            if (isRoleSpecified()) {
                // get specific realm role
                if (rolename == null) {
                    rolename = RoleOperations.getClientRoleNameFromId(adminRoot, realm, auth, cid, roleid);
                }
                super.uri = composeResourceUrl(adminRoot, realm, "roles/" + rolename);
            } else {
                // list defined realm roles
                super.uri = composeResourceUrl(adminRoot, realm, "roles");
            }
        }

        super.process();
    }

    private boolean isRoleSpecified() {
        return roleid != null || rolename != null;
    }

    private boolean isClientSpecified() {
        return cid != null || cclientid != null;
    }

    private boolean isGroupSpecified() {
        return gid != null || gname != null || gpath != null;
    }

    private boolean isCompositeRoleSpecified() {
        return rid != null || rname != null;
    }

    private boolean isUserSpecified() {
        return uid != null || uusername != null;
    }

    @Override
    protected boolean nothingToDo() {
        return false;
    }

    @Override
    protected String help() {
        StringWriter sb = new StringWriter();
        PrintWriter out = new PrintWriter(sb);
        out.println("Usage: " + CMD + " get-roles [--cclientid CLIENT_ID | --cid ID] [ARGUMENTS]");
        out.println("       " + CMD + " get-roles (--uusername USERNAME | --uid ID) [--cclientid CLIENT_ID | --cid ID] [--available | --effective | --all] (ARGUMENTS)");
        out.println("       " + CMD + " get-roles (--gname NAME | --gpath PATH | --gid ID) [--cclientid CLIENT_ID | --cid ID] [--available | --effective | --all] [ARGUMENTS]");
        out.println("       " + CMD + " get-roles (--rname ROLE_NAME | --rid ROLE_ID) [--cclientid CLIENT_ID | --cid ID] [--available | --effective | --all] [ARGUMENTS]");
        out.println();
        out.println("Command to list realm or client roles of a realm, a user, a group or a composite role.");
        out.println();
        out.println("Use '" + CMD + " config credentials' to establish an authenticated session, or use CREDENTIALS OPTIONS");
        out.println("to perform one time authentication.");
        out.println();
        out.println("If client is specified using --cclientid or --cid then client roles are listed, otherwise realm roles are listed.");
        out.println("If user is specified using --uusername or --uid then roles are listed for a specific user.");
        out.println("If group is specified using --gname, --gpath or --gid then roles are listed for a specific group.");
        out.println("If composite role is specified --rname or --rid then roles are listed for a specific composite role.");
        out.println("If neither user nor group, nor composite role is specified then defined roles are listed for a realm or specific client.");
        out.println("If role is specified using --rolename or --roleid then only that specific role is returned.");
        out.println("If --available is specified, then only roles not yet added to the target user or group are returned.");
        out.println("If --effective is specified, then roles added to the target user or group are transitively resolved and a full");
        out.println("set of roles in effect for that user, group or composite role is returned.");
        out.println("If --all is specified, then client roles for all clients are returned in addition to realm roles.");
        globalOptions(out);
        out.println("    --uusername               User's 'username'. If more than one user exists with the same username");
        out.println("                              you'll have to use --uid to specify the target user");
        out.println("    --uid                     User's 'id' attribute");
        out.println("    --gname                   Group's 'name'. If more than one group exists with the same name you'll have");
        out.println("                              to use --gid, or --gpath to specify the target group");
        out.println("    --gpath                   Group's 'path' attribute");
        out.println("    --gid                     Group's 'id' attribute");
        out.println("    --rname                   Composite role's 'name' attribute");
        out.println("    --rid                     Composite role's 'id' attribute");
        out.println("    --cclientid               Client's 'clientId' attribute");
        out.println("    --cid                     Client's 'id' attribute");
        out.println("    --rolename                Role's 'name' attribute");
        out.println("    --roleid                  Role's 'id' attribute");
        out.println("    --available               Return available roles - those that can still be added");
        out.println("    --effective               Return effective roles - transitively taking composite roles into account");
        out.println("    --all                     Return all client roles in addition to realm roles");
        out.println();
        out.println("    -H, --print-headers       Print response headers");
        out.println("    -F, --fields FILTER       A filter pattern to specify which fields of a JSON response to output");
        out.println("                              Use '" + CMD + " get --help' for more info on FILTER syntax.");
        out.println("    -c, --compressed          Don't pretty print the output");
        out.println("    --format FORMAT           Set output format to comma-separated-values by using 'csv'. Default format is 'json'");
        out.println("    --noquotes                Don't quote strings when output format is 'csv'");
        out.println("    -a, --admin-root URL      URL of Admin REST endpoint root if not default - e.g. http://localhost:8080/admin");
        out.println("    -r, --target-realm REALM  Target realm to issue requests against if not the one authenticated against");
        out.println();
        out.println("Examples:");
        out.println();
        out.println("Get all realm roles defined on a realm:");
        out.println("  " + PROMPT + " " + CMD + " get-roles -r demorealm");
        out.println();
        out.println("Get all client roles defined on a specific client, displaying only 'id' and 'name':");
        out.println("  " + PROMPT + " " + CMD + " get-roles -r demorealm --cclientid realm-management --fields id,name");
        out.println();
        out.println("List all realm roles for a specific user:");
        out.println("  " + PROMPT + " " + CMD + " get-roles -r demorealm --uusername testuser");
        out.println();
        out.println("List effective client roles for 'realm-management' client for a specific user:");
        out.println("  " + PROMPT + " " + CMD + " get-roles -r demorealm --uusername testuser --cclientid realm-management --effective");
        out.println();
        out.println();
        out.println("Use '" + CMD + " help' for general information and a list of commands");
        return sb.toString();
    }
}
