/*
 * This file is part of Aliucord, an Android Discord client mod.
 * Copyright (c) 2021 Juby210 & Vendicated
 * Licensed under the Open Software License version 3.0
 */

package com.aliucord.coreplugins.slashcommandsfix;

import com.aliucord.Logger;

import org.json.JSONArray;
import org.json.JSONObject;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * Diagnostic logging for failing application commands (e.g. localized ones).
 * <p>
 * Uses org.json and reflection on field names only, because Discord's bundled
 * Gson is obfuscated. Never logs option values (they may contain user input).
 */
final class Diagnostics {
    private static final int MAX_EXAMPLES = 10;

    private Diagnostics() {}

    /**
     * Logs which fields the index returns and every command/option whose
     * localized name differs from its name.
     */
    static void logIndexShape(Logger logger, String endpoint, String json) {
        try {
            var root = new JSONObject(json);
            var commands = root.optJSONArray("application_commands");
            if (commands == null) {
                logger.info("[diag] " + endpoint + ": no application_commands, keys=" + keys(root));
                return;
            }

            var commandKeys = new TreeSet<String>();
            var optionKeys = new TreeSet<String>();
            var examples = new ArrayList<String>();
            int localized = 0;

            for (int i = 0; i < commands.length(); i++) {
                var command = commands.optJSONObject(i);
                if (command == null) continue;
                commandKeys.addAll(keys(command));
                var prefix = "/" + command.optString("name");
                if (isLocalized(command)) {
                    localized++;
                    addExample(examples, prefix + " -> \"" + command.optString("name_localized") + "\" (id " + command.optString("id") + ")");
                }
                localized += collectOptions(command.optJSONArray("options"), prefix, optionKeys, examples);
            }

            logger.info("[diag] " + endpoint + ": " + commands.length() + " commands, " + localized + " localized names"
                + "\n  command keys: " + commandKeys
                + "\n  option keys: " + optionKeys
                + (examples.isEmpty() ? "" : "\n  name -> name_localized:\n    " + String.join("\n    ", examples)));
        } catch (Throwable e) {
            logger.error("[diag] failed to inspect " + endpoint, e);
        }
    }

    private static int collectOptions(JSONArray options, String prefix, TreeSet<String> optionKeys, List<String> examples) {
        if (options == null) return 0;
        int localized = 0;
        for (int i = 0; i < options.length(); i++) {
            var option = options.optJSONObject(i);
            if (option == null) continue;
            optionKeys.addAll(keys(option));
            var path = prefix + " " + option.optString("name");
            if (isLocalized(option)) {
                localized++;
                addExample(examples, path + " -> \"" + option.optString("name_localized") + "\"");
            }
            localized += collectOptions(option.optJSONArray("options"), path, optionKeys, examples);
        }
        return localized;
    }

    private static boolean isLocalized(JSONObject object) {
        return object.has("name_localized")
            && !object.isNull("name_localized")
            && !object.optString("name_localized").equals(object.optString("name"));
    }

    private static void addExample(List<String> examples, String example) {
        if (examples.size() < MAX_EXAMPLES) examples.add(example);
    }

    private static List<String> keys(JSONObject object) {
        var result = new ArrayList<String>();
        var it = object.keys();
        while (it.hasNext()) result.add(it.next());
        return result;
    }

    /**
     * Logs a failed application command: what was sent (names only) and
     * everything Discord said about why it was rejected.
     */
    static void logCommandFailure(Logger logger, Object result, Object localSendData, Object errorResponse) {
        try {
            var sb = new StringBuilder("[diag] application command failed: ")
                .append(result == null ? "null" : result.getClass().getSimpleName());

            if (localSendData != null) {
                sb.append("\n  sent: /").append(field(localSendData, "applicationCommandName"))
                    .append(" id=").append(field(localSendData, "applicationCommandId"))
                    .append(" version=").append(field(localSendData, "version"))
                    .append(" guild=").append(field(localSendData, "commandGuildId"))
                    .append("\n  option names: ").append(optionNames(field(localSendData, "applicationCommandsValues")));
            }

            if (errorResponse != null) {
                sb.append("\n  response: code=").append(field(errorResponse, "code"))
                    .append(" message=").append(field(errorResponse, "message"));
                var skemaError = field(errorResponse, "skemaError");
                if (skemaError != null) {
                    var lines = new ArrayList<String>();
                    flattenSkemaError(skemaError, "", lines);
                    for (var line : lines) sb.append("\n    ").append(line);
                }
            }

            logger.warn(sb.toString());
        } catch (Throwable e) {
            logger.error("[diag] failed to describe command failure", e);
        }
    }

    private static String optionNames(Object values) {
        if (!(values instanceof List)) return String.valueOf(values);
        var names = new ArrayList<String>();
        for (var value : (List<?>) values) {
            if (value == null) continue;
            var name = String.valueOf(field(value, "name"));
            var nested = field(value, "options");
            names.add(nested instanceof List && !((List<?>) nested).isEmpty() ? name + " " + optionNames(nested) : name);
        }
        return names.toString();
    }

    @SuppressWarnings("unchecked")
    private static void flattenSkemaError(Object skemaError, String path, List<String> lines) {
        var errors = field(skemaError, "errors");
        if (errors instanceof List) {
            for (var item : (List<?>) errors) {
                lines.add((path.isEmpty() ? "(root)" : path) + ": " + field(item, "code") + " " + field(item, "message"));
            }
        }
        var subErrors = field(skemaError, "subErrors");
        if (subErrors instanceof Map) {
            for (var entry : ((Map<String, Object>) subErrors).entrySet()) {
                flattenSkemaError(entry.getValue(), path.isEmpty() ? entry.getKey() : path + "." + entry.getKey(), lines);
            }
        }
    }

    /** Reads a (possibly private) field by name, walking up superclasses. Returns null if missing. */
    private static Object field(Object target, String name) {
        if (target == null) return null;
        for (Class<?> cls = target.getClass(); cls != null; cls = cls.getSuperclass()) {
            try {
                Field f = cls.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(target);
            } catch (NoSuchFieldException ignored) {
            } catch (Throwable e) {
                return "<" + e.getClass().getSimpleName() + ">";
            }
        }
        return null;
    }
}
