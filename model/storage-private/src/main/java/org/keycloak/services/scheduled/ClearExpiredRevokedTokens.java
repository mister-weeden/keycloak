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

package org.keycloak.services.scheduled;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.session.RevokedTokenPersisterProvider;
import org.keycloak.timer.ScheduledTask;

/**
 * Clear all expired revoked tokens.
 */
public class ClearExpiredRevokedTokens implements ScheduledTask {

    protected static final Logger logger = Logger.getLogger(ClearExpiredRevokedTokens.class);

    public static final String TASK_NAME = "ClearExpiredRevokedTokens";

    @Override
    public void run(KeycloakSession session) {
        long currentTimeMillis = Time.currentTimeMillis();

        session.getProvider(RevokedTokenPersisterProvider.class).expireTokens();

        long took = Time.currentTimeMillis() - currentTimeMillis;
        logger.debugf("%s finished in %d ms", getTaskName(), took);
    }

    @Override
    public String getTaskName() {
        return TASK_NAME;
    }
}
