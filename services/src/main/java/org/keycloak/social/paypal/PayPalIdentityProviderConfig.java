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
package org.keycloak.social.paypal;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

/**
 * @author Petter Lysne (petterlysne at hotmail dot com)
 */
public class PayPalIdentityProviderConfig extends OAuth2IdentityProviderConfig {

    public PayPalIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public PayPalIdentityProviderConfig() {
        
    }

    public boolean targetSandbox() {
        String sandbox = getConfig().get("sandbox");
        return sandbox == null ? false : Boolean.valueOf(sandbox);
    }

    public void setSandbox(boolean sandbox) {
        getConfig().put("sandbox", String.valueOf(sandbox));
    }

}
