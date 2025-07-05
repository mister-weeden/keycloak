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
import org.keycloak.common.Profile;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.SessionExpirationUtils;
import org.keycloak.models.utils.SessionTimeoutHelper;

import java.util.concurrent.TimeUnit;

/**
 * Handles session validation logic extracted from AuthenticationManager
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 */
public class SessionValidationManager {
    
    private static final Logger logger = Logger.getLogger(SessionValidationManager.class);
    
    public static boolean isSessionValid(RealmModel realm, UserSessionModel userSession) {
        if (userSession == null) {
            logger.debug("No user session");
            return false;
        }
        if (userSession.getNote(Details.IDENTITY_PROVIDER) != null) {
            String brokerAlias = userSession.getNote(Details.IDENTITY_PROVIDER);
            if (realm.getIdentityProviderByAlias(brokerAlias) == null) {
                // associated idp was removed, invalidate the session.
                return false;
            }
        }
        long currentTime = Time.currentTimeMillis();
        long lifespan = SessionExpirationUtils.calculateUserSessionMaxLifespanTimestamp(userSession.isOffline(),
                userSession.isRememberMe(), TimeUnit.SECONDS.toMillis(userSession.getStarted()), realm);
        long idle = SessionExpirationUtils.calculateUserSessionIdleTimestamp(userSession.isOffline(),
                userSession.isRememberMe(), TimeUnit.SECONDS.toMillis(userSession.getLastSessionRefresh()), realm);

        boolean sessionIdleOk = idle > currentTime -
                                       ((Profile.isFeatureEnabled(Profile.Feature.PERSISTENT_USER_SESSIONS) || Profile.isFeatureEnabled(Profile.Feature.CLUSTERLESS)) ? 0 : TimeUnit.SECONDS.toMillis(SessionTimeoutHelper.IDLE_TIMEOUT_WINDOW_SECONDS));
        boolean sessionMaxOk = lifespan == -1L || lifespan > currentTime;
        return sessionIdleOk && sessionMaxOk;
    }

    public static boolean isClientSessionValid(RealmModel realm, ClientModel client,
            UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        if (userSession == null || clientSession == null) {
            logger.debug("No user session");
            return false;
        }
        long currentTime = Time.currentTimeMillis();
        long lifespan = SessionExpirationUtils.calculateClientSessionMaxLifespanTimestamp(userSession.isOffline(),
                userSession.isRememberMe(), TimeUnit.SECONDS.toMillis(clientSession.getStarted()),
                TimeUnit.SECONDS.toMillis(userSession.getStarted()), realm, client);
        long idle = SessionExpirationUtils.calculateClientSessionIdleTimestamp(userSession.isOffline(),
                userSession.isRememberMe(), TimeUnit.SECONDS.toMillis(clientSession.getTimestamp()), realm, client);

        boolean sessionIdleOk = idle > currentTime -
                                       ((Profile.isFeatureEnabled(Profile.Feature.PERSISTENT_USER_SESSIONS) || Profile.isFeatureEnabled(Profile.Feature.CLUSTERLESS)) ? 0 : TimeUnit.SECONDS.toMillis(SessionTimeoutHelper.IDLE_TIMEOUT_WINDOW_SECONDS));
        boolean sessionMaxOk = lifespan == -1L || lifespan > currentTime;
        return sessionIdleOk && sessionMaxOk;
    }
}