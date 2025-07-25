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

package org.keycloak.quarkus.runtime.cli.command;

import static org.keycloak.exportimport.ExportImportConfig.ACTION_IMPORT;

import org.keycloak.config.OptionCategory;
import org.keycloak.exportimport.ExportImportConfig;
import org.keycloak.quarkus.runtime.configuration.mappers.ImportPropertyMappers;
import picocli.CommandLine.Command;

import java.util.EnumSet;

@Command(name = Import.NAME,
        header = "Import data from a directory or a file.",
        description = "%nImport data from a directory or a file.")
public final class Import extends AbstractNonServerCommand {

    public static final String NAME = "import";

    @Override
    protected void doBeforeRun() {
        if (System.getProperty(ExportImportConfig.REPLACE_PLACEHOLDERS) == null) {
            ExportImportConfig.setReplacePlaceholders(true);
        }
        ExportImportConfig.setAction(ACTION_IMPORT);
    }

    @Override
    public void validateConfig() {
        ImportPropertyMappers.validateConfig();
        super.validateConfig();
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    protected EnumSet<OptionCategory> excludedCategories() {
        return EnumSet.of(OptionCategory.EXPORT);
    }

}
