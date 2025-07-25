/*
 * Copyright 2025 Scott Weeden and/or his affiliates
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

package org.keycloak.models.cache;

import org.keycloak.provider.Spi;

public class CacheCrlProviderSpi implements Spi {

    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public String getName() {
        return "crlCache";
    }

    @Override
    public Class<CacheCrlProvider> getProviderClass() {
        return CacheCrlProvider.class;
    }

    @Override
    public Class<CacheCrlProviderFactory> getProviderFactoryClass() {
        return CacheCrlProviderFactory.class;
    }
}
