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

import org.keycloak.Config;
import org.keycloak.migration.ModelVersion;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class MigrateTo1_9_0 implements Migration {

    public static final ModelVersion VERSION = new ModelVersion("1.9.0");

    public ModelVersion getVersion() {
        return VERSION;
    }

    public void migrate(KeycloakSession session) {
        RealmModel realm = session.realms().getRealmByName(Config.getAdminRealm());
        if (realm != null && realm.getDisplayNameHtml() != null && realm.getDisplayNameHtml().equals("<strong>Keycloak</strong>")) {
            realm.setDisplayNameHtml("<div class=\"kc-logo-text\"><span>Keycloak</span></div>");
        }
    }

}
