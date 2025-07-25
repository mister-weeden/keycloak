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

package org.keycloak.testsuite.auth.page;

import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;

/**
 * Context path of Keycloak auth server.
 * 
 * URL: http://localhost:${auth.server.http.port}/auth
 * 
 * @author tkyjovsk
 */
public class AuthServer extends AuthServerContextRoot {

    @Override
    public UriBuilder createUriBuilder() {
        return super.createUriBuilder().path("auth");
    }

    public String getAuthRoot() {
        URI uri = buildUri();
        return uri.getScheme() + "://" + uri.getAuthority() + "/auth";
    }

//    @ArquillianResource
//    protected Keycloak keycloak;
//
//    public Keycloak keycloak() {
//        return keycloak;
//    }

}
