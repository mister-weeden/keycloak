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
package org.keycloak.social.facebook;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

/**
 * @author Pedro Igor
 */
public class FacebookIdentityProviderFactory extends AbstractIdentityProviderFactory<FacebookIdentityProvider> implements SocialIdentityProviderFactory<FacebookIdentityProvider> {

    public static final String PROVIDER_ID = "facebook";

    @Override
    public String getName() {
        return "Facebook";
    }

    @Override
    public FacebookIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new FacebookIdentityProvider(session, new FacebookIdentityProviderConfig(model));
    }

    @Override
    public OAuth2IdentityProviderConfig createConfig() {
        return new OAuth2IdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property().name("fetchedFields")
                .label("Additional user's profile fields")
                .helpText("Provide additional fields which would be fetched using the profile request. This will be appended to the default set of 'id,name,email,first_name,last_name'.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add().build();
    }
}
