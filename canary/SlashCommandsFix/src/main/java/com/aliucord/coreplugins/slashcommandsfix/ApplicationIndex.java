/*
 * This file is part of Aliucord, an Android Discord client mod.
 * Copyright (c) 2021 Juby210 & Vendicated
 * Licensed under the Open Software License version 3.0
 */

package com.aliucord.coreplugins.slashcommandsfix;

import java.lang.IllegalAccessException;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class ApplicationIndex {
    public Map<Long, Application> applications;
    public Map<Long, RemoteApplicationCommand> applicationCommands;

    public ApplicationIndex(Map<Long, Application> applications, Map<Long, RemoteApplicationCommand> applicationCommands) {
        this.applications = applications;
        this.applicationCommands = applicationCommands;
    }

    /**
     * Merges indexes. Earlier indexes take priority, so pass the guild/DM index
     * before the user index: an application present in both keeps its
     * guild-level permissions instead of the (empty) user-level ones.
     */
    public ApplicationIndex(List<ApplicationIndex> applicationIndexes) {
        this.applications = new HashMap<>();
        this.applicationCommands = new HashMap<>();
        for (var applicationIndex: applicationIndexes) {
            applicationIndex.applications.forEach(this.applications::putIfAbsent);
            applicationIndex.applicationCommands.forEach(this.applicationCommands::putIfAbsent);
        }
    }

    public void populateCommandCounts(Field applicationCommandCountField) throws IllegalAccessException {
        var applicationCommandCounts = new HashMap<Long, Integer>();
        for (var applicationCommand: this.applicationCommands.values()) {
            var count = applicationCommandCounts.getOrDefault(applicationCommand.getApplicationId(), 0);
            count += 1;
            applicationCommandCounts.put(applicationCommand.getApplicationId(), count);
        }
        for (var application: this.applications.values()) {
            applicationCommandCountField.setInt(application, applicationCommandCounts.getOrDefault(application.getId(), 0));
        }
    }
}
