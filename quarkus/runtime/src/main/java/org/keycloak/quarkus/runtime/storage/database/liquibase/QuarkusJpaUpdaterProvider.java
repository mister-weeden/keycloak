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

package org.keycloak.quarkus.runtime.storage.database.liquibase;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import liquibase.Scope;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.updater.JpaUpdaterProvider;
import org.keycloak.connections.jpa.updater.liquibase.LiquibaseConstants;
import org.keycloak.connections.jpa.updater.liquibase.ThreadLocalSessionContext;
import org.keycloak.connections.jpa.updater.liquibase.conn.CustomChangeLogHistoryService;
import org.keycloak.connections.jpa.updater.liquibase.conn.KeycloakLiquibase;
import org.keycloak.connections.jpa.updater.liquibase.conn.LiquibaseConnectionProvider;
import org.keycloak.connections.jpa.util.JpaUtils;
import org.keycloak.models.KeycloakSession;

import liquibase.Contexts;
import liquibase.LabelExpression;
import liquibase.Liquibase;
import liquibase.changelog.ChangeLogHistoryService;
import liquibase.changelog.ChangeLogHistoryServiceFactory;
import liquibase.changelog.ChangeSet;
import liquibase.changelog.RanChangeSet;
import liquibase.database.Database;
import liquibase.exception.DatabaseException;
import liquibase.exception.LiquibaseException;
import liquibase.executor.Executor;
import liquibase.executor.ExecutorService;
import liquibase.executor.LoggingExecutor;
import liquibase.snapshot.SnapshotControl;
import liquibase.snapshot.SnapshotGeneratorFactory;
import liquibase.statement.SqlStatement;
import liquibase.statement.core.AddColumnStatement;
import liquibase.statement.core.SetNullableStatement;
import liquibase.statement.core.UpdateStatement;
import liquibase.structure.core.Column;
import liquibase.structure.core.Table;
import liquibase.util.StreamUtil;

public class QuarkusJpaUpdaterProvider implements JpaUpdaterProvider {

    private static final Logger logger = Logger.getLogger(QuarkusJpaUpdaterProvider.class);

    public static final String CHANGELOG = "META-INF/jpa-changelog-master.xml";
    private static final String DEPLOYMENT_ID_COLUMN = "DEPLOYMENT_ID";
    public static final String VERIFY_AND_RUN_MASTER_CHANGELOG = "VERIFY_AND_RUN_MASTER_CHANGELOG";

    private final KeycloakSession session;
    private Map<String, List<ChangeSet>> changeSets = new HashMap<>();

    public QuarkusJpaUpdaterProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void update(Connection connection, String defaultSchema) {
        update(connection, null, defaultSchema);
    }

    @Override
    public void export(Connection connection, String defaultSchema, File file) {
        update(connection, file, defaultSchema);
    }

    private void update(Connection connection, File file, String defaultSchema) {
        logger.debug("Starting database update");

        // Need ThreadLocal as liquibase doesn't seem to have API to inject custom objects into tasks
        ThreadLocalSessionContext.setCurrentSession(session);

        Writer exportWriter = null;
        try {
            if (needVerifyMasterChangelog()) {
                // Run update with keycloak master changelog first
                KeycloakLiquibase liquibase = getLiquibaseForKeycloakUpdate(connection, defaultSchema);
                if (file != null) {
                    exportWriter = new FileWriter(file);
                }
                updateChangeSet(liquibase, exportWriter);
            }

            // Run update for each custom JpaEntityProvider
            Set<JpaEntityProvider> jpaProviders = session.getAllProviders(JpaEntityProvider.class);
            for (JpaEntityProvider jpaProvider : jpaProviders) {
                String customChangelog = jpaProvider.getChangelogLocation();
                if (customChangelog != null) {
                    String factoryId = jpaProvider.getFactoryId();
                    String changelogTableName = JpaUtils.getCustomChangelogTableName(factoryId);
                    KeycloakLiquibase liquibase = getLiquibaseForCustomProviderUpdate(connection, defaultSchema, customChangelog, jpaProvider.getClass().getClassLoader(), changelogTableName);
                    updateChangeSet(liquibase, exportWriter);
                }
            }
        } catch (LiquibaseException | IOException e) {
            throw new RuntimeException("Failed to update database", e);
        } finally {
            ThreadLocalSessionContext.removeCurrentSession();
            if (exportWriter != null) {
                try {
                    exportWriter.close();
                } catch (IOException ioe) {
                    // ignore
                }
            }
        }
    }

    private Boolean needVerifyMasterChangelog() {
        return session.getAttributeOrDefault(VERIFY_AND_RUN_MASTER_CHANGELOG, Boolean.TRUE);
    }

    protected void updateChangeSet(KeycloakLiquibase liquibase, Writer exportWriter) throws LiquibaseException  {
        String changelog = liquibase.getChangeLogFile();
        Database database = liquibase.getDatabase();
        Table changelogTable = SnapshotGeneratorFactory.getInstance().getDatabaseChangeLogTable(new SnapshotControl(database, false, Table.class, Column.class), database);

        if (changelogTable != null) {
            boolean hasDeploymentIdColumn = changelogTable.getColumn(DEPLOYMENT_ID_COLUMN) != null;

            // create DEPLOYMENT_ID column if it doesn't exist
            if (!hasDeploymentIdColumn) {
                ChangeLogHistoryService changelogHistoryService = getChangeLogHistoryService().getChangeLogService(database);
                changelogHistoryService.generateDeploymentId();
                String deploymentId = changelogHistoryService.getDeploymentId();

                logger.debugv("Adding missing column {0}={1} to {2} table", DEPLOYMENT_ID_COLUMN, deploymentId,changelogTable.getName());

                List<SqlStatement> statementsToExecute = new ArrayList<>();
                statementsToExecute.add(new AddColumnStatement(database.getLiquibaseCatalogName(), database.getLiquibaseSchemaName(),
                        changelogTable.getName(), DEPLOYMENT_ID_COLUMN, "VARCHAR(10)", null));
                statementsToExecute.add(new UpdateStatement(database.getLiquibaseCatalogName(), database.getLiquibaseSchemaName(), changelogTable.getName())
                        .addNewColumnValue(DEPLOYMENT_ID_COLUMN, deploymentId));
                statementsToExecute.add(new SetNullableStatement(database.getLiquibaseCatalogName(), database.getLiquibaseSchemaName(),
                        changelogTable.getName(), DEPLOYMENT_ID_COLUMN, "VARCHAR(10)", false));

                ExecutorService executorService = Scope.getCurrentScope().getSingleton(ExecutorService.class);
                Executor executor = executorService.getExecutor(LiquibaseConstants.JDBC_EXECUTOR, liquibase.getDatabase());

                for (SqlStatement sql : statementsToExecute) {
                    executor.execute(sql);
                    database.commit();
                }
            }
        }

        List<ChangeSet> changeSets = getLiquibaseUnrunChangeSets(liquibase);
        if (!changeSets.isEmpty()) {
            List<RanChangeSet> ranChangeSets = liquibase.getDatabase().getRanChangeSetList();
            if (ranChangeSets.isEmpty()) {
                logger.infov("Initializing database schema. Using changelog {0}", changelog);
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debugv("Updating database from {0} to {1}. Using changelog {2}", ranChangeSets.get(ranChangeSets.size() - 1).getId(), changeSets.get(changeSets.size() - 1).getId(), changelog);
                } else {
                    logger.infov("Updating database. Using changelog {0}", changelog);
                }
            }

            if (exportWriter != null) {
                if (ranChangeSets.isEmpty()) {
                    outputChangeLogTableCreationScript(liquibase, exportWriter);
                }
                liquibase.update(null, new LabelExpression(), exportWriter, false);
            } else {
                liquibase.update((Contexts) null);
            }

            logger.debugv("Completed database update for changelog {0}", changelog);
        } else {
            logger.debugv("Database is up to date for changelog {0}", changelog);
        }

        // Needs to restart liquibase services to clear ChangeLogHistoryServiceFactory.getInstance().
        // See https://issues.jboss.org/browse/KEYCLOAK-3769 for discussion relevant to why reset needs to be here
        resetLiquibaseServices(liquibase);
    }

    private void outputChangeLogTableCreationScript(Liquibase liquibase, final Writer exportWriter) throws DatabaseException {
        Database database = liquibase.getDatabase();

        ExecutorService executorService = Scope.getCurrentScope().getSingleton(ExecutorService.class);
        Executor oldTemplate = executorService.getExecutor(LiquibaseConstants.JDBC_EXECUTOR, database);
        LoggingExecutor loggingExecutor = new LoggingExecutor(executorService.getExecutor(LiquibaseConstants.JDBC_EXECUTOR, database), exportWriter, database);
        executorService.setExecutor(LiquibaseConstants.JDBC_EXECUTOR, database, loggingExecutor);

        loggingExecutor.comment("*********************************************************************");
        loggingExecutor.comment("* Keycloak database creation script - apply this script to empty DB *");
        loggingExecutor.comment("*********************************************************************" + StreamUtil.getLineSeparator());

        // DatabaseChangeLogTable is automatically added to the script by Liquibase
        // DatabaseChangeLogLockTable is created before this code is executed and recreated if it does not exist automatically
        // in org.keycloak.connections.jpa.updater.liquibase.lock.CustomLockService.init() called indirectly from
        // KeycloakApplication constructor (search for waitForLock() call). Hence it is not included in the creation script.

        executorService.setExecutor(LiquibaseConstants.JDBC_EXECUTOR, database, oldTemplate);
    }

    @Override
    public Status validate(Connection connection, String defaultSchema) {
        logger.debug("Validating if database is updated");
        ThreadLocalSessionContext.setCurrentSession(session);

        try {
            if (needVerifyMasterChangelog()) {
                // Validate with keycloak master changelog first
                KeycloakLiquibase liquibase = getLiquibaseForKeycloakUpdate(connection, defaultSchema);

                Status status = validateChangeSet(liquibase, liquibase.getChangeLogFile());
                if (status != Status.VALID) {
                    return status;
                }
            }

            // Validate each custom JpaEntityProvider
            Set<JpaEntityProvider> jpaProviders = session.getAllProviders(JpaEntityProvider.class);
            for (JpaEntityProvider jpaProvider : jpaProviders) {
                String customChangelog = jpaProvider.getChangelogLocation();
                if (customChangelog != null) {
                    String factoryId = jpaProvider.getFactoryId();
                    String changelogTableName = JpaUtils.getCustomChangelogTableName(factoryId);
                    KeycloakLiquibase liquibase = getLiquibaseForCustomProviderUpdate(connection, defaultSchema, customChangelog, jpaProvider.getClass().getClassLoader(), changelogTableName);
                    if (validateChangeSet(liquibase, liquibase.getChangeLogFile()) != Status.VALID) {
                        return Status.OUTDATED;
                    }
                }
            }
        } catch (LiquibaseException e) {
            throw new RuntimeException("Failed to validate database", e);
        }

        return Status.VALID;
    }

    protected Status validateChangeSet(KeycloakLiquibase liquibase, String changelog) throws LiquibaseException {
        final Status result;
        List<ChangeSet> changeSets = getLiquibaseUnrunChangeSets(liquibase);

        if (!changeSets.isEmpty()) {
            if (changeSets.size() == liquibase.getDatabaseChangeLog().getChangeSets().size()) {
                result = Status.EMPTY;
            } else {
                logger.debugf("Validation failed. Database is not up-to-date for changelog %s", changelog);
                result = Status.OUTDATED;
            }
        } else {
            logger.debugf("Validation passed. Database is up-to-date for changelog %s", changelog);
            result = Status.VALID;
        }

        // Needs to restart liquibase services to clear ChangeLogHistoryServiceFactory.getInstance().
        // See https://issues.jboss.org/browse/KEYCLOAK-3769 for discussion relevant to why reset needs to be here
        resetLiquibaseServices(liquibase);

        return result;
    }

    private void resetLiquibaseServices(KeycloakLiquibase liquibase) {
        liquibase.resetServices();
        getChangeLogHistoryService().register(new CustomChangeLogHistoryService());
    }

    private ChangeLogHistoryServiceFactory getChangeLogHistoryService() {
        return Scope.getCurrentScope().getSingleton(ChangeLogHistoryServiceFactory.class);
    }

    private List<ChangeSet> getLiquibaseUnrunChangeSets(Liquibase liquibase) {
        // we don't need to fetch change sets if they were previously obtained
        return changeSets.computeIfAbsent(liquibase.getChangeLogFile(), s -> {
            try {
                return liquibase.listUnrunChangeSets(null, new LabelExpression(), false);
            } catch (LiquibaseException e) {
                throw new RuntimeException(e);
            }
        });
    }

    private KeycloakLiquibase getLiquibaseForKeycloakUpdate(Connection connection, String defaultSchema) throws LiquibaseException {
        LiquibaseConnectionProvider liquibaseProvider = session.getProvider(LiquibaseConnectionProvider.class);
        return liquibaseProvider.getLiquibase(connection, defaultSchema);
    }

    private KeycloakLiquibase getLiquibaseForCustomProviderUpdate(Connection connection, String defaultSchema, String changelogLocation, ClassLoader classloader, String changelogTableName) throws LiquibaseException {
        LiquibaseConnectionProvider liquibaseProvider = session.getProvider(LiquibaseConnectionProvider.class);
        return liquibaseProvider.getLiquibaseForCustomUpdate(connection, defaultSchema, changelogLocation, classloader, changelogTableName);
    }

    @Override
    public void close() {
        changeSets.clear();
        changeSets = null;
    }

}
