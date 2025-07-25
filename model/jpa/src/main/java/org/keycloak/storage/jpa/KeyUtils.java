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
package org.keycloak.storage.jpa;

import java.util.regex.Pattern;
import org.jboss.logging.Logger;
import org.keycloak.models.light.LightweightUserAdapter;

/**
 *
 * @author hmlnarik
 */
public class KeyUtils {

    private static final Logger LOG = Logger.getLogger(KeyUtils.class);

    public static final Pattern UUID_PATTERN = Pattern.compile("[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}");
    public static final Pattern SHORT_ID_PATTERN = Pattern.compile("[0-9A-Za-z_-]{22}");

    public static final Pattern EXPECTED_KEY_PATTERN = Pattern.compile(
      UUID_PATTERN.pattern()
      + "|"
      + "f:(" + UUID_PATTERN.pattern() + "|" + SHORT_ID_PATTERN.pattern() + "):.*"
      + "|"
      + LightweightUserAdapter.ID_PREFIX + UUID_PATTERN.pattern()
    );

    /**
     * Check if a string is a valid key.
     * @param key String representation of the key
     * @return true when the key is {@code null} or either a plain UUID or a key formatted as "f:[UUID]:any_string" or "f:[SHORT_ID]:any_string"
     */
    public static boolean isValidKey(String key) {
        return key == null || EXPECTED_KEY_PATTERN.matcher(key).matches();
    }

    /**
     * Logs a warning when the key is not a valid key
     * @param key String representation of the key
     */
    public static void assertValidKey(String key) throws IllegalArgumentException {
        if (! isValidKey(key)) {
            LOG.warnf("The given key is not a valid key per specification, future migration might fail: %s", key);
        }
    }
}
