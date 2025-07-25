/*
 * Copyright 2020 Scott Weeden and/or his affiliates
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
package test.org.keycloak.quarkus.services.health;

import static io.restassured.RestAssured.given;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;

@QuarkusTest
@TestProfile(MetricsEnabledProfile.class)
class KeycloakMetricsConfigurationTest {

    @BeforeEach
    void setUp() {
        RestAssured.port = 9001;
    }

    @Test
    void testMetrics() {
        given().basePath("/")
                .when().get("prom/metrics")
                .then()
                .statusCode(200);
    }

    @Test
    void testWrongMetricsEndpoints() {
        given().basePath("/")
                .when().get("metrics")
                .then()
                // Metrics are available under `/prom/metrics` (see quarkus.micrometer.export.prometheus.path)
                // so /metrics should return 404.
                .statusCode(404);
    }
}
