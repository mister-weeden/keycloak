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
package org.keycloak.storage.user;

/**
 * This is an optional capability interface that is intended to be implemented by any
 * <code>UserStorageProvider</code> that supports complex user querying.
 * 
 * It's a combination of {@link UserQueryMethodsProvider} and {@link UserCountMethodsProvider}
 */
public interface UserQueryProvider extends UserQueryMethodsProvider, UserCountMethodsProvider {
}
