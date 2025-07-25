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
package org.keycloak.common.util;

import java.io.File;
import java.util.Optional;

/**
 * A utility class for replacing properties in strings.
 *
 * @author <a href="mailto:jason@planet57.com">Jason Dillon</a>
 * @author <a href="Scott.Stark@jboss.org">Scott Stark</a>
 * @author <a href="claudio.vesco@previnet.it">Claudio Vesco</a>
 * @author <a href="mailto:adrian@jboss.com">Adrian Brock</a>
 * @author <a href="mailto:dimitris@jboss.org">Dimitris Andreadis</a>
 * @version <tt>$Revision: 2898 $</tt>
 */
public final class StringPropertyReplacer
{

    /** File separator value */
    private static final String FILE_SEPARATOR = File.separator;

    /** Path separator value */
    private static final String PATH_SEPARATOR = File.pathSeparator;

    /** File separator alias */
    private static final String FILE_SEPARATOR_ALIAS = "/";

    /** Path separator alias */
    private static final String PATH_SEPARATOR_ALIAS = ":";

    // States used in property parsing
    private static final int NORMAL = 0;
    private static final int SEEN_DOLLAR = 1;
    private static final int IN_BRACKET = 2;

    private static final PropertyResolver NULL_RESOLVER = property -> null;
    private static PropertyResolver DEFAULT_PROPERTY_RESOLVER;

    public static void setDefaultPropertyResolver(PropertyResolver systemVariables) {
        DEFAULT_PROPERTY_RESOLVER = systemVariables;
    }

    /**
     * Go through the input string and replace any occurrence of ${p} with
     * the System.getProperty(p) value. If there is no such property p defined,
     * then the ${p} reference will remain unchanged.
     *
     * If the property reference is of the form ${p:v} and there is no such property p,
     * then the default value v will be returned.
     *
     * If the property reference is of the form ${p1,p2} or ${p1,p2:v} then
     * the primary and the secondary properties will be tried in turn, before
     * returning either the unchanged input, or the default value.
     *
     * The property ${/} is replaced with System.getProperty("file.separator")
     * value and the property ${:} is replaced with System.getProperty("path.separator").
     *
     * @param string - the string with possible ${} references
     * @return the input string with all property references replaced if any.
     *    If there are no valid references the input string will be returned.
     */
    public static String replaceProperties(final String string) {
        return replaceProperties(string, getDefaultPropertyResolver());
    }

    /**
     * Go through the input string and replace any occurrence of ${p} with
     * the value resolves from {@code resolver}. If there is no such property p defined,
     * then the ${p} reference will remain unchanged.
     *
     * If the property reference is of the form ${p:v} and there is no such property p,
     * then the default value v will be returned.
     *
     * If the property reference is of the form ${p1,p2} or ${p1,p2:v} then
     * the primary and the secondary properties will be tried in turn, before
     * returning either the unchanged input, or the default value.
     *
     * The property ${/} is replaced with System.getProperty("file.separator")
     * value and the property ${:} is replaced with System.getProperty("path.separator").
     *
     * @param string - the string with possible ${} references
     * @param resolver - the property resolver
     * @return the input string with all property references replaced if any.
     *    If there are no valid references the input string will be returned.
     */
    public static String replaceProperties(final String string, PropertyResolver resolver)
    {
        if(string == null) {
            return null;
        }
        final char[] chars = string.toCharArray();
        StringBuilder buffer = new StringBuilder();
        boolean properties = false;
        int state = NORMAL;
        int start = 0;
        int openBracketsCount = 0;
        for (int i = 0; i < chars.length; ++i)
        {
            char c = chars[i];

            // Dollar sign outside brackets
            if (c == '$' && state != IN_BRACKET)
                state = SEEN_DOLLAR;

            // Open bracket immediately after dollar
            else if (c == '{' && state == SEEN_DOLLAR)
            {
                buffer.append(string.substring(start, i - 1));
                state = IN_BRACKET;
                start = i - 1;
                openBracketsCount = 1;
            }

            // Seeing open bracket after we already saw some open bracket without corresponding closed bracket. This causes "nested" expressions. For example ${foo:${bar}}
            else if (c == '{' && state == IN_BRACKET)
                openBracketsCount++;

            // No open bracket after dollar
            else if (state == SEEN_DOLLAR)
                state = NORMAL;

            // Seeing closed bracket, but we already saw more than one open bracket before. Hence "nested" expression is still not fully closed.
            // For example expression ${foo:${bar}} is closed after the second closed bracket, not after the first closed bracket.
            else if (c == '}' && state == IN_BRACKET && openBracketsCount > 1)
                openBracketsCount--;

                // Closed bracket after open bracket
            else if (c == '}' && state == IN_BRACKET)
            {
                // No content
                if (start + 2 == i)
                {
                    buffer.append("${}"); // REVIEW: Correct?
                }
                else // Collect the system property
                {
                    String value = null;

                    String key = string.substring(start + 2, i);

                    // check for alias
                    if (FILE_SEPARATOR_ALIAS.equals(key))
                    {
                        value = FILE_SEPARATOR;
                    }
                    else if (PATH_SEPARATOR_ALIAS.equals(key))
                    {
                        value = PATH_SEPARATOR;
                    }
                    else
                    {
                        // check from the properties
                        value = resolveValue(resolver, key);

                        if (value == null)
                        {
                            // Check for a default value ${key:default}
                            int colon = key.indexOf(':');
                            if (colon > 0)
                            {
                                String realKey = key.substring(0, colon);
                                value = resolveValue(resolver, realKey);

                                if (value == null)
                                {
                                    // Check for a composite key, "key1,key2"
                                    value = resolveCompositeKey(realKey, resolver);

                                    // Not a composite key either, use the specified default
                                    if (value == null)
                                        value = key.substring(colon+1);
                                }
                            }
                            else
                            {
                                // No default, check for a composite key, "key1,key2"
                                value = resolveCompositeKey(key, resolver);
                            }
                        }
                    }

                    if (value != null)
                    {
                        properties = true;
                        buffer.append(value);
                    }
                    else
                    {
                        buffer.append("${");
                        buffer.append(key);
                        buffer.append('}');
                    }

                }
                start = i + 1;
                state = NORMAL;
            }
        }

        // No properties
        if (!properties)
            return string;

        // Collect the trailing characters
        if (start != chars.length)
            buffer.append(string.substring(start, chars.length));

        if (buffer.indexOf("${") != -1) {
            try {
                return replaceProperties(buffer.toString(), resolver);
            } catch (StackOverflowError ex) {
                throw new IllegalStateException("Infinite recursion happening when replacing properties on '" + buffer + "'");
            }
        }

        // Done
        return buffer.toString();
    }

    private static String resolveCompositeKey(String key, PropertyResolver resolver)
    {
        String value = null;

        // Look for the comma
        int comma = key.indexOf(',');
        if (comma > -1)
        {
            // If we have a first part, try resolve it
            if (comma > 0)
            {
                // Check the first part
                String key1 = key.substring(0, comma);
                value = resolveValue(resolver, key1);
            }
            // Check the second part, if there is one and first lookup failed
            if (value == null && comma < key.length() - 1)
            {
                String key2 = key.substring(comma + 1);
                value = resolveValue(resolver, key2);
            }
        }
        // Return whatever we've found or null
        return value;
    }

    public interface PropertyResolver {
        String resolve(String property);
    }

    private static String resolveValue(PropertyResolver resolver, String key) {
        if (resolver == null) {
            return getDefaultPropertyResolver().resolve(key);
        }

        return resolver.resolve(key);
    }

    private static PropertyResolver getDefaultPropertyResolver() {
        return Optional.ofNullable(DEFAULT_PROPERTY_RESOLVER).orElse(NULL_RESOLVER);
    }
}
