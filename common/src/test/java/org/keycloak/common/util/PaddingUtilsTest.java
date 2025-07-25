/*
 * Copyright 2022 Scott Weeden and/or his affiliates
 *  and other contributors as indicated by the @author tags.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.keycloak.common.util;

import org.junit.Assert;
import org.junit.Test;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class PaddingUtilsTest {

    @Test
    public void testPadding() {
        Assert.assertEquals("foo123", PaddingUtils.padding("foo123", 5));
        Assert.assertEquals("foo123", PaddingUtils.padding("foo123", 6));
        Assert.assertEquals("foo123\0", PaddingUtils.padding("foo123", 7));

        Assert.assertEquals("someLongPassword", PaddingUtils.padding("someLongPassword", 14));
        Assert.assertEquals("short\0\0\0\0\0\0\0\0\0", PaddingUtils.padding("short", 14));
    }
}
