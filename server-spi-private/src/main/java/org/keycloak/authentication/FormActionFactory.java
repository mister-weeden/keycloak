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

package org.keycloak.authentication;

import org.keycloak.provider.ProviderFactory;

/**
 * Factory for instantiating FormAction objects.  This is a singleton and created when Keycloak boots.
 *
 * You must specify a file
 * META-INF/services/org.keycloak.authentication.FormActionFactory in the jar that this class is contained in
 * This file must have the fully qualified class name of all your FormActionFactory classes
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public interface FormActionFactory extends ProviderFactory<FormAction>, ConfigurableAuthenticatorFactory {
}
