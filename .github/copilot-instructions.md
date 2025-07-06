This file provides guidance to Claude Code (claude.ai/code) when working

     This is the mister-weeden repository containing a Keycloak deployment.
     Keycloak is an Open Source Identity and Access Management solution. The
     repository contains both the main Keycloak source code and custom theme
     configurations.

     ## Build and Development Commands

     ### Prerequisites
     - Java JDK 17 or 21
     - Maven 3.9.8+ (use `./mvnw` wrapper)
     - Node.js 18+ with Corepack enabled
     - PNPM 10.4.1

     ### Building the Project

     ```bash
     # Full build
     ./keycloak/mvnw clean install

     # Build with distribution
     ./keycloak/mvnw clean install -Pdistribution

     # Quick build (skip tests)
     ./keycloak/mvnw clean install -DskipTests

     # Build server only
     ./keycloak/mvnw -pl quarkus/deployment,quarkus/dist -am -DskipTests clean
      install
     ```

     ### Running Keycloak

     ```bash
     # Development mode (from keycloak directory)
     java -jar quarkus/server/target/lib/quarkus-run.jar start-dev

     # Default credentials: admin/admin
     ```

     ### Frontend Development

     ```bash
     # Enable Corepack (one-time setup)
     corepack enable

     # Navigate to JS directory
     cd keycloak/js

     # Install dependencies
     pnpm install

     # Run development server with admin UI
     pnpm --filter keycloak-server start --admin-dev

     # Run only admin UI
     pnpm --filter keycloak-admin-ui run dev

     # Run account UI
     pnpm --filter keycloak-account-ui run dev
     ```

     ### Testing

     ```bash
     # Run base integration tests
     ./keycloak/mvnw -f testsuite/integration-arquillian/pom.xml clean install

     # Run single test
     ./keycloak/mvnw -f testsuite/integration-arquillian/pom.xml clean install
      -Dtest=LoginTest

     # Run tests in Quarkus mode
     ./keycloak/mvnw -f testsuite/integration-arquillian/pom.xml
     -Pauth-server-quarkus clean install

     # Run frontend E2E tests
     cd keycloak/js/apps/admin-ui
     pnpm test
     ```

     ### Linting and Type Checking

     ```bash
     # JavaScript/TypeScript linting
     cd keycloak/js
     pnpm lint

     # Run type checking
     pnpm type-check
     ```

     ## Architecture Overview

     ### Project Structure

     The repository follows a multi-module Maven structure with these key
     components:

     1. **Backend (Java/Quarkus)**
        - `keycloak/core/` - Core functionality and APIs
        - `keycloak/services/` - Main service implementations
        - `keycloak/model/` - Data model and storage layers
        - `keycloak/quarkus/` - Quarkus-specific runtime
        - `keycloak/federation/` - User federation providers (LDAP, Kerberos)

     2. **Frontend (TypeScript/React)**
        - `keycloak/js/apps/admin-ui/` - Administrator console
        - `keycloak/js/apps/account-ui/` - User account management console
        - `keycloak/js/libs/` - Shared libraries and components

     3. **Themes**
        - `keycloak/themes/` - Built-in Keycloak themes
        - `keycloak-themes/` - Custom themes directory (needs to be created
     for custom client themes)

     ### Key Architectural Patterns

     1. **Provider Architecture**: Keycloak uses a provider/SPI pattern for
     extensibility. New features are typically implemented as providers.

     2. **Event-Driven**: Uses event listeners for cross-cutting concerns like
      auditing and integration.

     3. **Caching**: Infinispan is used for distributed caching in cluster
     deployments.

     4. **Storage**: Supports multiple databases through JPA with
     database-specific optimizations.

     5. **Theming**: Flexible theming system with inheritance - themes can
     extend parent themes and override specific resources.

     ### Custom Theme Development

     When creating custom themes:
     1. Create theme directory under `keycloak-themes/`
     2. Add `keycloak-themes.json` to register themes
     3. Each theme needs `theme.properties` specifying parent theme and
     customizations
     4. Theme types: login, account, admin, email, welcome

     ### Important Development Notes

     1. **Commit Signing**: All commits must be signed with `--signoff`

     2. **Database Migrations**: Schema changes require Liquibase changesets
     in the model module

     3. **Provider Registration**: New providers must be registered in
     `META-INF/services/`

     4. **Frontend State**: Admin UI uses React with PatternFly components

     5. **Testing Strategy**:
        - Unit tests in individual modules
        - Integration tests in `testsuite/integration-arquillian/`
        - E2E tests using Playwright for UI

     6. **Build Profiles**:
        - `distribution` - Builds full distribution
        - `auth-server-quarkus` - Uses Quarkus runtime for tests
        - `jpa-performance` - Runs JPA performance tests

     The project emphasizes modularity, extensibility through SPIs, and
     comprehensive testing across all layers.