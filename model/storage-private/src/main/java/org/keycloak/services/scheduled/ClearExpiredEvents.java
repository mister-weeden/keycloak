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
import org.keycloak.events.EventStoreProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.timer.ScheduledTask;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class ClearExpiredEvents implements ScheduledTask {

    protected static final Logger logger = Logger.getLogger(ClearExpiredEvents.class);

    @Override
    public void run(KeycloakSession session) {
        long currentTimeMillis = Time.currentTimeMillis();

        EventStoreProvider eventStore = session.getProvider(EventStoreProvider.class);
        if (eventStore != null) {
            eventStore.clearExpiredEvents();
        }

        long took = Time.currentTimeMillis() - currentTimeMillis;
        logger.debugf("ClearExpiredEvents finished in %d ms", took);
    }

}
