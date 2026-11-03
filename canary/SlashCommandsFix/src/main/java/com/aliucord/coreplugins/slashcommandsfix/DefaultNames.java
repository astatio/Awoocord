/*
 * This file is part of Aliucord, an Android Discord client mod.
 * Copyright (c) 2021 Juby210 & Vendicated
 * Licensed under the Open Software License version 3.0
 */

package com.aliucord.coreplugins.slashcommandsfix;

import org.json.JSONArray;
import org.json.JSONObject;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Lets the client show localized command names while sending the default ones.
 * <p>
 * This Discord version has no localization support: whatever is in a command's
 * {@code name} (and its options' names) is both displayed and sent back when the
 * command runs. Discord only accepts the default names in interactions, so we fetch
 * the command index twice (localized for display, unlocalized for sending), map
 * localized names to default ones per command, and rewrite the outgoing payload.
 * <p>
 * JSON is read with org.json and Discord's classes through field names, because
 * Discord's bundled Gson and getters are obfuscated.
 */
final class DefaultNames {
    /** Default name of a command or option, plus localized-to-default mappings of its child options. */
    private static final class Node {
        final String defaultName;
        final Map<String, Node> options;

        Node(String defaultName, Map<String, Node> options) {
            this.defaultName = defaultName;
            this.options = options;
        }
    }

    /** Keyed by command id (as sent in the interaction). */
    private final Map<String, Node> commands = new ConcurrentHashMap<>();

    /**
     * Records the default names of every command in {@code localizedJson}, matching
     * commands by id and options by position (localization doesn't reorder them).
     */
    void update(String localizedJson, String defaultJson) throws Exception {
        var localizedCommands = new JSONObject(localizedJson).optJSONArray("application_commands");
        var defaultCommands = new JSONObject(defaultJson).optJSONArray("application_commands");
        if (localizedCommands == null || defaultCommands == null) return;

        var defaultsById = new HashMap<String, JSONObject>();
        for (int i = 0; i < defaultCommands.length(); i++) {
            var command = defaultCommands.optJSONObject(i);
            if (command != null) defaultsById.put(command.optString("id"), command);
        }

        for (int i = 0; i < localizedCommands.length(); i++) {
            var localized = localizedCommands.optJSONObject(i);
            if (localized == null) continue;
            var id = localized.optString("id");
            var defaults = defaultsById.get(id);
            if (defaults == null) continue;
            commands.put(id, new Node(
                defaults.optString("name"),
                align(localized.optJSONArray("options"), defaults.optJSONArray("options"))
            ));
        }
    }

    private static Map<String, Node> align(JSONArray localized, JSONArray defaults) {
        if (localized == null || defaults == null) return Collections.emptyMap();
        var result = new HashMap<String, Node>();
        for (int i = 0; i < Math.min(localized.length(), defaults.length()); i++) {
            var lo = localized.optJSONObject(i);
            var de = defaults.optJSONObject(i);
            // Positions should always line up; bail out on this option if they somehow don't
            if (lo == null || de == null || lo.optInt("type") != de.optInt("type")) continue;
            result.put(lo.optString("name"), new Node(
                de.optString("name"),
                align(lo.optJSONArray("options"), de.optJSONArray("options"))
            ));
        }
        return result;
    }

    // Fields of com.discord.api.commands.ApplicationCommandData / ApplicationCommandValue
    private final Field dataIdField;
    private final Field dataNameField;
    private final Field dataOptionsField;
    private final Field valueNameField;
    private final Field valueOptionsField;

    DefaultNames(Class<?> dataClass, Class<?> valueClass) throws NoSuchFieldException {
        dataIdField = accessible(dataClass, "id");
        dataNameField = accessible(dataClass, "name");
        dataOptionsField = accessible(dataClass, "options");
        valueNameField = accessible(valueClass, "name");
        valueOptionsField = accessible(valueClass, "options");
    }

    private static Field accessible(Class<?> cls, String name) throws NoSuchFieldException {
        var field = cls.getDeclaredField(name);
        field.setAccessible(true);
        return field;
    }

    /**
     * Rewrites a freshly built interaction {@code data} object in place so its command and
     * option names are the defaults. Leaves it untouched for unknown commands.
     */
    void applyTo(Object data) throws IllegalAccessException {
        if (data == null) return;
        var command = commands.get(String.valueOf(dataIdField.get(data)));
        if (command == null) return;
        if (!command.defaultName.isEmpty()) {
            dataNameField.set(data, command.defaultName);
        }
        applyToValues(dataOptionsField.get(data), command.options);
    }

    private void applyToValues(Object values, Map<String, Node> options) throws IllegalAccessException {
        if (!(values instanceof List) || options.isEmpty()) return;
        for (var value : (List<?>) values) {
            if (value == null) continue;
            var option = options.get(String.valueOf(valueNameField.get(value)));
            if (option == null) continue;
            if (!option.defaultName.isEmpty()) {
                valueNameField.set(value, option.defaultName);
            }
            applyToValues(valueOptionsField.get(value), option.options);
        }
    }
}
