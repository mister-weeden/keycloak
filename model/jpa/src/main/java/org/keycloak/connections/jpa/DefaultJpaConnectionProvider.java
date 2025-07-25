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

package org.keycloak.connections.jpa;

import org.jboss.logging.Logger;

import jakarta.persistence.EntityManager;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class DefaultJpaConnectionProvider implements JpaConnectionProvider {

    private static final Logger logger = Logger.getLogger(DefaultJpaConnectionProvider.class);
    private final EntityManager em;

    public DefaultJpaConnectionProvider(EntityManager em) {
        this.em = em;
    }

    @Override
    public EntityManager getEntityManager() {
        return em;
    }

    @Override
    public void close() {
        logger.trace("DefaultJpaConnectionProvider close()");
        em.close();
    }

}
