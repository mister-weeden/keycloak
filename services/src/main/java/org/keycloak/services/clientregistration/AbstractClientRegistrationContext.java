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

package org.keycloak.services.clientregistration;

import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.ClientRepresentation;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public abstract class AbstractClientRegistrationContext implements ClientRegistrationContext {

    protected final KeycloakSession session;
    protected final ClientRepresentation client;
    protected final ClientRegistrationProvider provider;

    public AbstractClientRegistrationContext(KeycloakSession session, ClientRepresentation client, ClientRegistrationProvider provider) {
        this.session = session;
        this.client = client;
        this.provider = provider;
    }

    @Override
    public ClientRepresentation getClient() {
        return client;
    }

    @Override
    public KeycloakSession getSession() {
        return session;
    }

    @Override
    public ClientRegistrationProvider getProvider() {
        return provider;
    }

}
