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

package org.keycloak.adapters.saml.profile.webbrowsersso;

import org.keycloak.adapters.saml.OnSessionCreated;
import org.keycloak.adapters.saml.SamlDeployment;
import org.keycloak.adapters.saml.SamlSessionStore;
import org.keycloak.adapters.saml.profile.SamlInvocationContext;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.adapters.spi.HttpFacade;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class BrowserHandler extends WebBrowserSsoAuthenticationHandler {
    public BrowserHandler(HttpFacade facade, SamlDeployment deployment, SamlSessionStore sessionStore) {
        super(facade, deployment, sessionStore);
    }

    @Override
    public AuthOutcome handle(OnSessionCreated onCreateSession) {
        return doHandle(new SamlInvocationContext(null, null, null), onCreateSession);
    }
}
