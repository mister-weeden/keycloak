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
package org.keycloak.services.managers;

import org.jboss.logging.Logger;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.common.util.Time;
import org.keycloak.cookie.CookieProvider;
import org.keycloak.cookie.CookieType;
import org.keycloak.http.HttpRequest;
import org.keycloak.jose.jws.crypto.HashUtils;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IdentityCookieToken;
import org.keycloak.services.Urls;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.util.TokenUtil;

import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Handles cookie operations extracted from AuthenticationManager
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 */
public class CookieManager {
    
    private static final Logger logger = Logger.getLogger(CookieManager.class);
    
    public static IdentityCookieToken createIdentityToken(KeycloakSession keycloakSession, RealmModel realm, UserModel user, UserSessionModel session, String issuer) {
        IdentityCookieToken token = new IdentityCookieToken();
        token.id(SecretGenerator.getInstance().generateSecureID());
        token.issuedNow();
        token.subject(user.getId());
        token.issuer(issuer);
        token.type(TokenUtil.TOKEN_TYPE_KEYCLOAK_ID);

        if (session != null) {
            token.setSessionId(session.getId());
        }

        if (session != null && session.isRememberMe() && realm.getSsoSessionMaxLifespanRememberMe() > 0) {
            token.exp((long) Time.currentTime() + realm.getSsoSessionMaxLifespanRememberMe());
        } else if (realm.getSsoSessionMaxLifespan() > 0) {
            token.exp((long) Time.currentTime() + realm.getSsoSessionMaxLifespan());
        }

        String stateChecker = (String) keycloakSession.getAttribute("state_checker");
        if (stateChecker == null) {
            stateChecker = Base64Url.encode(SecretGenerator.getInstance().randomBytes());
            keycloakSession.setAttribute("state_checker", stateChecker);
        }
        token.getOtherClaims().put("state_checker", stateChecker);

        return token;
    }

    public static void createLoginCookie(KeycloakSession keycloakSession, RealmModel realm, UserModel user, UserSessionModel session, UriInfo uriInfo, ClientConnection connection) {
        Objects.requireNonNull(session, "User session cannot be null");
        String issuer = Urls.realmIssuer(uriInfo.getBaseUri(), realm.getName());
        IdentityCookieToken identityCookieToken = createIdentityToken(keycloakSession, realm, user, session, issuer);
        String encoded = keycloakSession.tokens().encode(identityCookieToken);
        int maxAge = NewCookie.DEFAULT_MAX_AGE;
        if (session.isRememberMe()) {
            maxAge = realm.getSsoSessionMaxLifespanRememberMe() > 0 ? realm.getSsoSessionMaxLifespanRememberMe() : realm.getSsoSessionMaxLifespan();
        }
        keycloakSession.getProvider(CookieProvider.class).set(CookieType.IDENTITY, encoded, maxAge);

        String sessionCookieValue = sha256UrlEncodedHash(session.getId());

        // THIS SHOULD NOT BE A HTTPONLY COOKIE!  It is used for OpenID Connect Iframe Session support!
        // Max age should be set to the max lifespan of the session as it's used to invalidate old-sessions on re-login
        int sessionCookieMaxAge = session.isRememberMe() && realm.getSsoSessionMaxLifespanRememberMe() > 0 ? realm.getSsoSessionMaxLifespanRememberMe() : realm.getSsoSessionMaxLifespan();
        keycloakSession.getProvider(CookieProvider.class).set(CookieType.SESSION, sessionCookieValue, sessionCookieMaxAge);
    }

    public static void createRememberMeCookie(String username, UriInfo uriInfo, KeycloakSession session) {
        KeycloakContext context = session.getContext();
        RealmModel realm = context.getRealm();
        ClientConnection connection = context.getConnection();
        String path = getRealmCookiePath(realm, uriInfo);
        boolean secureOnly = realm.getSslRequired().isRequired(connection);
        // remember me cookie should be persistent (hardcoded to 365 days for now)
        // NOTE: httpOnly flag is now set by the CookieProvider implementation
        session.getProvider(CookieProvider.class).set(CookieType.LOGIN_HINT, "username:" + URLEncoder.encode(username, StandardCharsets.UTF_8));
    }

    public static String getRememberMeUsername(KeycloakSession session) {
        if (session.getContext().getRealm().isRememberMe()) {
            String value = session.getProvider(CookieProvider.class).get(CookieType.LOGIN_HINT);
            if (value != null) {
                String[] s = value.split(":");
                if (s[0].equals("username") && s.length == 2) {
                    return URLDecoder.decode(s[1], StandardCharsets.UTF_8);
                }
            }
        }
        return null;
    }

    public static void expireIdentityCookie(KeycloakSession session) {
        session.getProvider(CookieProvider.class).expire(CookieType.IDENTITY);
        session.getProvider(CookieProvider.class).expire(CookieType.SESSION);
    }

    public static void expireRememberMeCookie(KeycloakSession session) {
        session.getProvider(CookieProvider.class).expire(CookieType.LOGIN_HINT);
    }

    public static void expireAuthSessionCookie(KeycloakSession session) {
        session.getProvider(CookieProvider.class).expire(CookieType.AUTH_SESSION_ID);
    }

    public static String getRealmCookiePath(RealmModel realm, UriInfo uriInfo) {
        URI uri = RealmsResource.realmBaseUrl(uriInfo).build(realm.getName());
        // KEYCLOAK-5270
        return uri.getRawPath() + "/";
    }

    public static boolean compareSessionIdWithSessionCookie(KeycloakSession session, String sessionId) {
        Objects.requireNonNull(sessionId, "Session id cannot be null");

        String cookie = session.getProvider(CookieProvider.class).get(CookieType.SESSION);
        if (cookie == null || cookie.isEmpty()) {
            logger.debugv("Could not find cookie: {0}", AuthenticationManager.KEYCLOAK_SESSION_COOKIE);
            return false;
        }

        if (cookie.equals(sha256UrlEncodedHash(sessionId))) return true;

        // Backwards compatibility
        String[] split = cookie.split("/");
        if (split.length >= 3) {
            String oldSessionId = split[2];
            return !sessionId.equals(oldSessionId);
        }
        return false;
    }

    public static String sha256UrlEncodedHash(String input) {
        return HashUtils.sha256UrlEncodedHash(input, StandardCharsets.ISO_8859_1);
    }
}