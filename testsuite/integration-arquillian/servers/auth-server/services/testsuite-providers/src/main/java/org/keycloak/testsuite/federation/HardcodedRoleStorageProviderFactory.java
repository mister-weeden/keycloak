/*
 * Copyright 2020 Scott Weeden and/or his affiliates
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
package org.keycloak.testsuite.federation;

import java.util.List;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.role.RoleStorageProviderFactory;
import org.keycloak.storage.role.RoleStorageProviderModel;

public class HardcodedRoleStorageProviderFactory implements RoleStorageProviderFactory<HardcodedRoleStorageProvider> {
    @Override
    public HardcodedRoleStorageProvider create(KeycloakSession session, ComponentModel model) {
        return new HardcodedRoleStorageProvider(new RoleStorageProviderModel(model));
    }

    public static final String PROVIDER_ID = "hardcoded-role";
    public static final String ROLE_NAME = "role_name";
    public static final String DELAYED_SEARCH = "delayed_search";

    protected static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
                .property().name(ROLE_NAME)
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("Hardcoded Role Name")
                .helpText("Only this role naem is available for lookup")
                .defaultValue("hardcoded-role")
                .add()
                .property().name(DELAYED_SEARCH)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .label("Delayes provider by 5s.")
                .helpText("If true it delayes search for clients within the provider by 5s.")
                .defaultValue("false")
                .add()
                .build();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
