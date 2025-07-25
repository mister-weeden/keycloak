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

package org.keycloak.migration.migrators;


import org.keycloak.migration.ModelVersion;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.RealmRepresentation;

import java.util.stream.Collectors;

/**
 * @author <a href="mailto:bruno@abstractj.org">Bruno Oliveira</a>
 */
public class MigrateTo3_4_2 implements Migration {

    public static final ModelVersion VERSION = new ModelVersion("3.4.2");

    @Override
    public void migrate(KeycloakSession session) {
        session.realms().getRealmsStream().forEach(this::migrateRealm);
    }

    @Override
    public void migrateImport(KeycloakSession session, RealmModel realm, RealmRepresentation rep, boolean skipUserDependent) {
        migrateRealm(realm);
    }

    protected void migrateRealm(RealmModel realm) {
        // this is a fix for migration that should have been done in 3_2_0
        ClientModel cli = realm.getClientByClientId(Constants.ADMIN_CLI_CLIENT_ID);
        clearScope(cli);
        ClientModel console = realm.getClientByClientId(Constants.ADMIN_CONSOLE_CLIENT_ID);
        clearScope(console);

    }

    private void clearScope(ClientModel cli) {
        if (cli.isFullScopeAllowed()) cli.setFullScopeAllowed(false);
        cli.getScopeMappingsStream().collect(Collectors.toList()).forEach(cli::deleteScopeMapping);
    }

    @Override
    public ModelVersion getVersion() {
        return VERSION;
    }

}
