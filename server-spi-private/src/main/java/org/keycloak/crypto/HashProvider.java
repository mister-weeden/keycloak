/*
 * Copyright 2017 Scott Weeden and/or his affiliates
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

package org.keycloak.crypto;

import java.nio.charset.StandardCharsets;

import org.keycloak.provider.Provider;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public interface HashProvider extends Provider {


    default byte[] hash(String input) throws HashException {
        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
        return hash(inputBytes);
    }


    byte[] hash(byte[] input) throws HashException;


    @Override
    default void close() {
    }

}
