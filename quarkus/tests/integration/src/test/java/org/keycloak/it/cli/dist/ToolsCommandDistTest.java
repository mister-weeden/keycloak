/*
 * Copyright 2023 Scott Weeden and/or his affiliates
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

package org.keycloak.it.cli.dist;

import io.quarkus.test.junit.main.Launch;
import io.quarkus.test.junit.main.LaunchResult;

import org.junit.jupiter.api.Test;
import org.keycloak.it.junit5.extension.DistributionTest;

import static org.junit.jupiter.api.Assertions.assertTrue;

@DistributionTest
public class ToolsCommandDistTest {

    @Test
    @Launch({ "tools", "completion" })
    void initialCompletionShouldSucceed(LaunchResult result) {
        assertTrue(result.getOutput().contains("Define a completion specification"),
                () -> "The Output:\n" + result.getOutput() + "doesn't contains the expected string.");
    }

}
