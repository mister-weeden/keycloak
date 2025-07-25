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

package org.keycloak.federation.sssd;

import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder;
import org.freedesktop.dbus.exceptions.DBusException;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.federation.sssd.impl.AvailabilityChecker;
import org.keycloak.federation.sssd.impl.PAMAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.UserStorageProviderModel;

/**
 * @author <a href="mailto:bruno@abstractj.org">Bruno Oliveira</a>
 * @version $Revision: 1 $
 */
public class SSSDFederationProviderFactory implements UserStorageProviderFactory<SSSDFederationProvider>, EnvironmentDependentProviderFactory {

    private static final String PROVIDER_NAME = "sssd";
    private static final Logger logger = Logger.getLogger(SSSDFederationProvider.class);

    private volatile DBusConnection dbusConnection;

    @Override
    public String getId() {
        return PROVIDER_NAME;
    }

    @Override
    public SSSDFederationProvider create(KeycloakSession session, ComponentModel model) {
        lazyInit();
        return new SSSDFederationProvider(session, new UserStorageProviderModel(model), this);
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {
        if (dbusConnection != null) {
            dbusConnection.disconnect();
        }
    }

    protected PAMAuthenticator createPAMAuthenticator(String username, String... factors) {
        return new PAMAuthenticator(username, factors);
    }

    protected DBusConnection getDbusConnection() {
        return dbusConnection;
    }

    private void lazyInit() {
        if (dbusConnection == null) {
            synchronized (this) {
                if (dbusConnection == null) {
                    try {
                        dbusConnection = DBusConnectionBuilder.forSystemBus().build();
                    } catch(DBusException e) {
                        // should not happen as it should be supported to get this point
                        throw new IllegalStateException("Cannot create DBUS connection", e);
                    }
                }
            }
        }
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return AvailabilityChecker.isAvailable();
    }
}
