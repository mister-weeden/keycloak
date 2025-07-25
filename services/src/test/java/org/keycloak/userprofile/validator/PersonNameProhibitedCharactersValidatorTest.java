/*
 * Copyright 2021 Scott Weeden and/or his affiliates
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
package org.keycloak.userprofile.validator;

import org.junit.Assert;
import org.junit.Test;

/**
 * @author Vlastimil Elias <velias@redhat.com>
 */
public class PersonNameProhibitedCharactersValidatorTest {
    
    @Test
    public void allowed() {
        // letters and numbers
        assertValid("a");
        assertValid("A");
        assertValid("z");
        assertValid("Z");
        assertValid("0");
        assertValid("9");
        //other than ASCII alphabets
        assertValid("\u010D");
        assertValid("\u01B1");
        assertValid("\u0397");
        assertValid("\u98CE\u7720");
        
        // symbols we want to be allowed
        assertValid(" ");
        assertValid(".");
        assertValid("-");
        assertValid("_");
        assertValid("@");
        assertValid("'");
        assertValid(":");
        assertValid(",");
        
        assertValid("as tr");

        //crazy but existing name ;-)
        assertValid("X \u00C6 A-12");
    }
    
    @Test
    public void disallowed() {
        
        // white and control characters
        assertInvalid("\t");
        assertInvalid("\n");
        assertInvalid("\f");
        assertInvalid("\r");
        assertInvalid("\u0000");
        
        //symbols dangerous for distinct technologies or really unnecessary in names
        //potential path traversals
        assertInvalid("/");
        assertInvalid("\\");
        //html/javascript dangerous
        assertInvalid("<");
        assertInvalid(">");
        assertInvalid("\"");
        assertInvalid("&");
        //other symbols not expected in names and potentially dangerous for other technologies
        assertInvalid("*");
        assertInvalid("$");
        assertInvalid("%");
        assertInvalid("#");
        assertInvalid("(");
        assertInvalid(")");
        assertInvalid("{");
        assertInvalid("}");
        assertInvalid("|");
        assertInvalid("~");
        assertInvalid("^");
        assertInvalid("!");
        assertInvalid("?");
        assertInvalid(";");
        assertInvalid("§");
        assertInvalid("=");
        
        //unexpected character between expected
        assertInvalid("as\ttr");
        assertInvalid("\tastr");
        assertInvalid("astr\t");
    }

    private void assertValid(String value) {
        Assert.assertTrue(PersonNameProhibitedCharactersValidator.INSTANCE.validate(value).isValid());
    }
    
    private void assertInvalid(String value) {
        Assert.assertFalse(PersonNameProhibitedCharactersValidator.INSTANCE.validate(value).isValid());
    }

}
