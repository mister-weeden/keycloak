/*
 * Copyright 2024 Scott Weeden and/or his affiliates
 *  and other contributors as indicated by the @author tags.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.keycloak.protocol.oidc;

import java.util.List;
import java.util.stream.Stream;

import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.representations.LogoutToken;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class LogoutTokenValidationContext {

    private final LogoutToken logoutToken;
    private final LogoutTokenValidationCode status;
    private final List<OIDCIdentityProvider> validIdentityProviders;

    LogoutTokenValidationContext(LogoutTokenValidationCode status) {
        this(status, null, null);
    }

    LogoutTokenValidationContext(LogoutTokenValidationCode status, LogoutToken logoutToken, List<OIDCIdentityProvider> validIdentityProviders) {
        this.logoutToken = logoutToken;
        this.status = status;
        this.validIdentityProviders = validIdentityProviders;
    }

    public LogoutToken getLogoutToken() {
        return logoutToken;
    }

    public LogoutTokenValidationCode getStatus() {
        return status;
    }

    public List<OIDCIdentityProvider> getValidIdentityProviders() {
        return validIdentityProviders;
    }
}
