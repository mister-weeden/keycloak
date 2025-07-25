/*
 * Copyright 2024 Scott Weeden and/or his affiliates
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

package org.keycloak.models.sessions.infinispan.remote.transaction;

import org.infinispan.commons.util.concurrent.CompletionStages;
import org.keycloak.models.AbstractKeycloakTransaction;
import org.keycloak.models.KeycloakTransaction;

/**
 * A {@link KeycloakTransaction} implementation that wraps all the user and client session transactions.
 * <p>
 * This implementation commits all modifications asynchronously and concurrently in both user and client sessions
 * transactions. Waits for all them to complete. This is an optimization to reduce the response time.
 */
public class UserSessionTransaction extends AbstractKeycloakTransaction {

    private final UserSessionChangeLogTransaction userSessions;
    private final ClientSessionChangeLogTransaction clientSessions;
    private final UserSessionChangeLogTransaction offlineUserSessions;
    private final ClientSessionChangeLogTransaction offlineClientSessions;

    public UserSessionTransaction(UserSessionChangeLogTransaction userSessions, UserSessionChangeLogTransaction offlineUserSessions, ClientSessionChangeLogTransaction clientSessions, ClientSessionChangeLogTransaction offlineClientSessions) {
        this.userSessions = userSessions;
        this.offlineUserSessions = offlineUserSessions;
        this.clientSessions = clientSessions;
        this.offlineClientSessions = offlineClientSessions;
    }


    @Override
    public void begin() {
        super.begin();
        userSessions.begin();
        clientSessions.begin();
        offlineUserSessions.begin();
        offlineClientSessions.begin();
    }

    @Override
    protected void commitImpl() {
        var stage = CompletionStages.aggregateCompletionStage();
        userSessions.commitAsync(stage);
        clientSessions.commitAsync(stage);
        offlineUserSessions.commitAsync(stage);
        offlineClientSessions.commitAsync(stage);
        CompletionStages.join(stage.freeze());
    }

    @Override
    protected void rollbackImpl() {
        userSessions.rollback();
        clientSessions.rollback();
        offlineUserSessions.rollback();
        offlineClientSessions.rollback();
    }

    public ClientSessionChangeLogTransaction getClientSessions(boolean offline) {
        return offline ? offlineClientSessions : clientSessions;
    }

    public UserSessionChangeLogTransaction getUserSessions(boolean offline) {
        return offline ? offlineUserSessions : userSessions;
    }

    public void removeAllSessionsByRealmId(String realmId) {
        clientSessions.getConditionalRemover().removeByRealmId(realmId);
        userSessions.getConditionalRemover().removeByRealmId(realmId);
        offlineClientSessions.getConditionalRemover().removeByRealmId(realmId);
        offlineUserSessions.getConditionalRemover().removeByRealmId(realmId);
    }

    public void removeOnlineSessionsByRealmId(String realmId) {
        clientSessions.getConditionalRemover().removeByRealmId(realmId);
        userSessions.getConditionalRemover().removeByRealmId(realmId);
    }

    public void removeAllSessionByUserId(String realmId, String userId) {
        userSessions.getConditionalRemover().removeByUserId(realmId, userId);
        clientSessions.getConditionalRemover().removeByUserId(realmId, userId);
    }

    public void removeUserSessionById(String userSessionId, boolean offline) {
        getUserSessions(offline).remove(userSessionId);
        getClientSessions(offline).removeByUserSessionId(userSessionId);
    }
}
