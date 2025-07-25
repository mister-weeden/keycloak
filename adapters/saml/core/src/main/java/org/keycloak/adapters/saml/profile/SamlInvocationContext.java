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

package org.keycloak.adapters.saml.profile;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class SamlInvocationContext {

    private String samlRequest;
    private String samlResponse;
    private String relayState;

    public SamlInvocationContext() {
        this(null, null, null);
    }

    public SamlInvocationContext(String samlRequest, String samlResponse, String relayState) {
        this.samlRequest = samlRequest;
        this.samlResponse = samlResponse;
        this.relayState = relayState;
    }

    public String getSamlRequest() {
        return this.samlRequest;
    }

    public String getSamlResponse() {
        return this.samlResponse;
    }

    public String getRelayState() {
        return this.relayState;
    }
}
