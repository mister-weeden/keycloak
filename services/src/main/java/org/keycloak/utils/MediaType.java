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

package org.keycloak.utils;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class MediaType {

    public static final String TEXT_HTML_UTF_8 = "text/html; charset=utf-8";
    public static final jakarta.ws.rs.core.MediaType TEXT_HTML_UTF_8_TYPE = new jakarta.ws.rs.core.MediaType("text", "html", "utf-8");

    public static final String TEXT_PLAIN_UTF_8 = "text/plain; charset=utf-8";
    public static final jakarta.ws.rs.core.MediaType TEXT_PLAIN_UTF_8_TYPE = new jakarta.ws.rs.core.MediaType("text", "plain", "utf-8");

    public static final String TEXT_PLAIN_JAVASCRIPT = "text/javascript; charset=utf-8";
    public static final jakarta.ws.rs.core.MediaType TEXT_JAVASCRIPT_UTF_8_TYPE = new jakarta.ws.rs.core.MediaType("text", "javascript", "utf-8");

    public static final String APPLICATION_JSON = jakarta.ws.rs.core.MediaType.APPLICATION_JSON;
    public static final jakarta.ws.rs.core.MediaType APPLICATION_JSON_TYPE = jakarta.ws.rs.core.MediaType.APPLICATION_JSON_TYPE;

    public static final String APPLICATION_FORM_URLENCODED = jakarta.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED;
    public static final jakarta.ws.rs.core.MediaType APPLICATION_FORM_URLENCODED_TYPE = jakarta.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED_TYPE;

    public static final String APPLICATION_JWT = "application/jwt";
    public static final String APPLICATION_JWKS = "application/jwk-set+json";
    public static final jakarta.ws.rs.core.MediaType APPLICATION_JWT_TYPE = new jakarta.ws.rs.core.MediaType("application", "jwt");

    public static final String APPLICATION_XML = jakarta.ws.rs.core.MediaType.APPLICATION_XML;

    public static final String TEXT_XML = jakarta.ws.rs.core.MediaType.TEXT_XML;

}
