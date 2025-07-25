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

package org.keycloak.protocol.oidc.utils;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public enum OIDCResponseMode {

    QUERY("query"),
    JWT("jwt"),
    FRAGMENT("fragment"),
    FORM_POST("form_post"),
    QUERY_JWT("query.jwt"),
    FRAGMENT_JWT("fragment.jwt"),
    FORM_POST_JWT("form_post.jwt");

    private String value;

    OIDCResponseMode(String v) {
        value = v;
    }

    public static OIDCResponseMode parse(String responseMode, OIDCResponseType responseType) {
        if (responseMode == null) {
            return getDefaultResponseMode(responseType);
        } else if(responseMode.equals("jwt")) {
            return getDefaultJarmResponseMode(responseType);
        } else {
            return fromValue(responseMode);
        }
    }

    public static OIDCResponseMode parseWhenInvalidResponseType(String responseMode) {
        if (responseMode == null) {
            return OIDCResponseMode.QUERY;
        } else if(responseMode.equals("jwt")) {
            return OIDCResponseMode.QUERY_JWT;
        } else {
            for (OIDCResponseMode c : OIDCResponseMode.values()) {
                if (c.value.equals(responseMode)) {
                    return c;
                }
            }
            return OIDCResponseMode.QUERY;
        }
    }

    public String value() {
        return value;
    }

    private static OIDCResponseMode fromValue(String v) {
        for (OIDCResponseMode c : OIDCResponseMode.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

    private static OIDCResponseMode getDefaultResponseMode(OIDCResponseType responseType) {
        if (responseType.isImplicitOrHybridFlow()) {
            return OIDCResponseMode.FRAGMENT;
        } else {
            return OIDCResponseMode.QUERY;
        }
    }

    private static OIDCResponseMode getDefaultJarmResponseMode(OIDCResponseType responseType) {
        if (responseType.isImplicitOrHybridFlow()) {
            return OIDCResponseMode.FRAGMENT_JWT;
        } else {
            return OIDCResponseMode.QUERY_JWT;
        }
    }
}
