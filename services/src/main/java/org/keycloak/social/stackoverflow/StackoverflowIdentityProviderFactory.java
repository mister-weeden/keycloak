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
package org.keycloak.social.stackoverflow;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

/**
 * @author Vlastimil Elias (velias at redhat dot com)
 */
public class StackoverflowIdentityProviderFactory extends
        AbstractIdentityProviderFactory<StackoverflowIdentityProvider> implements
        SocialIdentityProviderFactory<StackoverflowIdentityProvider> {

    public static final String PROVIDER_ID = "stackoverflow";

    @Override
    public String getName() {
        return "StackOverflow";
    }

    @Override
    public StackoverflowIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new StackoverflowIdentityProvider(session, new StackOverflowIdentityProviderConfig(model));
    }

    @Override
    public StackOverflowIdentityProviderConfig createConfig() {
        return new StackOverflowIdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property().name("key")
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("Key")
                .helpText("The Key obtained from Stack Overflow client registration.")
                .add().build();
    }
}
