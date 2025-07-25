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

package org.keycloak.connections.jpa.updater.liquibase.lock;

import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.dblock.DBLockProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class LiquibaseDBLockProviderFactory implements DBLockProviderFactory {

    private static final Logger logger = Logger.getLogger(LiquibaseDBLockProviderFactory.class);
    public static final int PROVIDER_PRIORITY = 1;

    private long lockWaitTimeoutMillis;

    protected long getLockWaitTimeoutMillis() {
        return lockWaitTimeoutMillis;
    }

    @Override
    public void init(Config.Scope config) {
        int lockWaitTimeout = config.getInt("lockWaitTimeout", 900);
        this.lockWaitTimeoutMillis = Time.toMillis(lockWaitTimeout);
        logger.debugf("Liquibase lock provider configured with lockWaitTime: %d seconds", lockWaitTimeout);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public LiquibaseDBLockProvider create(KeycloakSession session) {
        return new LiquibaseDBLockProvider(this, session);
    }

    @Override
    public void setTimeouts(long lockRecheckTimeMillis, long lockWaitTimeoutMillis) {
        this.lockWaitTimeoutMillis = lockWaitTimeoutMillis;
    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "jpa";
    }

    @Override
    public int order() {
        return PROVIDER_PRIORITY;
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name("lockWaitTimeout")
                .type("int")
                .helpText("The maximum time to wait when waiting to release a database lock.")
                .add().build();
    }
}
