/*
 * This file is part of Aliucord, an Android Discord client mod.
 * Copyright (c) 2021 Juby210 & Vendicated
 * Licensed under the Open Software License version 3.0
 */

package com.aliucord.coreplugins.slashcommandsfix;

import android.content.Context;
import android.util.Base64;

import com.aliucord.api.GatewayAPI;
import com.aliucord.Http;
import com.aliucord.Logger;
import com.aliucord.patcher.InsteadHook;
import com.aliucord.patcher.Patcher;
import com.aliucord.patcher.PreHook;
import com.aliucord.Utils;
import com.aliucord.utils.GsonUtils;
import com.aliucord.utils.RNSuperProperties;
import com.discord.api.channel.Channel;
import com.discord.models.commands.Application;
import com.discord.models.commands.ApplicationCommand;
import com.discord.models.commands.ApplicationCommandKt;
import com.discord.models.commands.ApplicationCommandLocalSendData;
import com.discord.stores.BuiltInCommandsProvider;
import com.discord.stores.StoreApplicationCommands;
import com.discord.stores.StoreApplicationCommands$requestApplicationCommands$1;
import com.discord.stores.StoreApplicationCommands$requestApplicationCommandsQuery$1;
import com.discord.stores.StoreApplicationInteractions;
import com.discord.stores.StoreChannelsSelected;
import com.discord.stores.StoreStream;
import com.discord.utilities.error.Error;
import com.discord.utilities.messagesend.MessageResult;
import com.discord.utilities.permissions.PermissionUtils;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

final class Patches {
    private ApplicationIndexCache applicationIndexCache;
    private Logger logger;
    private Method handleGuildApplicationsUpdateMethod;
    private Method handleDiscoverCommandsUpdateMethod;
    private Method handleQueryCommandsUpdateMethod;
    private Field applicationCommandCountField;
    private Field storeApplicationCommandsQueryField;
    private Field errorResponseErrorField;
    private Field skemaErrorSubErrorsField;
    private Field skemaErrorErrorsField;
    private Field skemaErrorItemCodeField;
    private Field skemaErrorItemMessageField;
    private Field storeApplicationCommandsBuiltInCommandsProviderField;

    Patches(Logger logger) throws Throwable {
        this.logger = logger;
        this.applicationIndexCache = new ApplicationIndexCache();
    }

    @SuppressWarnings("unchecked")
    public void loadPatches(Context context) throws Throwable {
        this.handleGuildApplicationsUpdateMethod = StoreApplicationCommands.class.getDeclaredMethod("handleGuildApplicationsUpdate", List.class);
        this.handleGuildApplicationsUpdateMethod.setAccessible(true);
        this.handleDiscoverCommandsUpdateMethod = StoreApplicationCommands.class.getDeclaredMethod("handleDiscoverCommandsUpdate", List.class);
        this.handleDiscoverCommandsUpdateMethod.setAccessible(true);
        this.handleQueryCommandsUpdateMethod = StoreApplicationCommands.class.getDeclaredMethod("handleQueryCommandsUpdate", List.class);
        this.handleQueryCommandsUpdateMethod.setAccessible(true);
        this.applicationCommandCountField = Application.class.getDeclaredField("commandCount");
        this.applicationCommandCountField.setAccessible(true);
        this.storeApplicationCommandsQueryField = StoreApplicationCommands.class.getDeclaredField("query");
        this.storeApplicationCommandsQueryField.setAccessible(true);
        this.errorResponseErrorField = Error.Response.class.getDeclaredField("skemaError");
        this.errorResponseErrorField.setAccessible(true);
        this.skemaErrorSubErrorsField = Error.SkemaError.class.getDeclaredField("subErrors");
        this.skemaErrorSubErrorsField.setAccessible(true);
        this.skemaErrorErrorsField = Error.SkemaError.class.getDeclaredField("errors");
        this.skemaErrorErrorsField.setAccessible(true);
        this.skemaErrorItemCodeField = Error.SkemaErrorItem.class.getDeclaredField("code");
        this.skemaErrorItemCodeField.setAccessible(true);
        this.skemaErrorItemMessageField = Error.SkemaErrorItem.class.getDeclaredField("message");
        this.skemaErrorItemMessageField.setAccessible(true);
        this.storeApplicationCommandsBuiltInCommandsProviderField = StoreApplicationCommands.class.getDeclaredField("builtInCommandsProvider");
        this.storeApplicationCommandsBuiltInCommandsProviderField.setAccessible(true);

        var storeApplicationCommands = StoreStream.getApplicationCommands();
        var storeChannelsSelected = StoreStream.getChannelsSelected();
        var storeUsers = StoreStream.getUsers();
        var storePermissions = StoreStream.getPermissions();
        var storeGuilds = StoreStream.getGuilds();

        // Browsing commands (when just a '/' is typed)
        Patcher.addPatch(
            StoreApplicationCommands$requestApplicationCommands$1.class.getDeclaredMethod("invoke"),
            new PreHook(param -> {
                var this_ = (StoreApplicationCommands$requestApplicationCommands$1) param.thisObject;

                if (this_.$guildId == null) {
                    return;
                }

                try {
                    var applicationIndexSource = Patches.applicationIndexSourceFromContext(this_.$guildId, storeChannelsSelected);
                    this.passCommandData(this_.this$0, applicationIndexSource, RequestSource.BROWSE);
                } catch (Throwable e) {
                    // Let Discord's original request run instead
                    this.logger.error("Failed to load application commands", e);
                    return;
                }

                param.setResult(null);
            })
        );

        // Completing commands
        Patcher.addPatch(
            StoreApplicationCommands$requestApplicationCommandsQuery$1.class.getDeclaredMethod("invoke"),
            new PreHook(param -> {
                var this_ = (StoreApplicationCommands$requestApplicationCommandsQuery$1) param.thisObject;

                if (this_.$guildId == null) {
                    return;
                }

                try {
                    var applicationIndexSource = Patches.applicationIndexSourceFromContext(this_.$guildId, storeChannelsSelected);
                    storeApplicationCommandsQueryField.set(this_.this$0, this_.$query);
                    this.passCommandData(this_.this$0, applicationIndexSource, RequestSource.QUERY);
                } catch (Throwable e) {
                    // Let Discord's original request run instead
                    this.logger.error("Failed to query application commands", e);
                    return;
                }

                param.setResult(null);
            })
        );

        // Command permission check
        Patcher.addPatch(
            ApplicationCommandKt.class.getDeclaredMethod("hasPermission", ApplicationCommand.class, long.class, List.class),
            new InsteadHook(param -> {
                var applicationCommand = (ApplicationCommand) param.args[0];
                var roleIds = (List<Long>) param.args[2];

                if (!(applicationCommand instanceof RemoteApplicationCommand)) {
                    // Allow all builtin commands
                    return true;
                }
                var remoteApplicationCommand = (RemoteApplicationCommand) applicationCommand;

                var channel = storeChannelsSelected.getSelectedChannel();
                if (channel == null) {
                    return false;
                }
                var guildId = channel.i();

                if (guildId == 0) {
                    // Allow all commands in DMs
                    return true;
                }

                // This check runs while the command list is rendered, so it must never hit
                // the network. The browse/query hooks fetch the indexes before Discord gets
                // here; a stale entry is still good enough for filtering (the server
                // enforces permissions on execution anyway).
                var applicationId = remoteApplicationCommand.getApplicationId();
                var isUser = this.applicationIndexCache
                    .getAny(new ApplicationIndexSourceUser().getEndpoint())
                    .map(index -> index.applications.containsKey(applicationId))
                    .orElse(false);
                if (isUser) {
                    // Allow all user application commands
                    return true;
                }
                var application = this.applicationIndexCache
                    .getAny(new ApplicationIndexSourceGuild(guildId).getEndpoint())
                    .map(index -> index.applications.get(applicationId))
                    .orElse(null);
                if (application == null) {
                    // Discord requested checking a command from the previous guild - ignore
                    // Some such requests are still processed (if the command exists in both guilds), but it's not an issue as the result doesn't matter for them anyways.
                    return false;
                }
                var user = storeUsers.getMe();
                var guild = storeGuilds.getGuild(guildId);
                if (user == null || guild == null) {
                    return false;
                }
                // Not computed yet -> treat as no permissions rather than throwing on unboxing
                Long guildPermissions = storePermissions.getGuildPermissions().get(guildId);
                long memberPermissions = guildPermissions != null ? guildPermissions : 0L;

                var applicationPermission = application.permissions_.checkFor(roleIds, channel, guild, memberPermissions, user, true);
                var commandPermission = remoteApplicationCommand.permissions_.checkFor(roleIds, channel, guild, memberPermissions, user, applicationPermission);

                return commandPermission;
            })
        );

        // Command error handling
        Patcher.addPatch(
            StoreApplicationInteractions.class.getDeclaredMethod("handleApplicationCommandResult", MessageResult.class, ApplicationCommandLocalSendData.class, Function0.class, Function1.class),
            new PreHook(param -> {
                var result = (MessageResult) param.args[0];
                var localSendData = (ApplicationCommandLocalSendData) param.args[1];

                if (result instanceof MessageResult.Success) {
                    return;
                }
                if (!(result instanceof MessageResult.UnknownFailure)) {
                    Diagnostics.logCommandFailure(this.logger, result, localSendData, null);
                    return;
                }

                // Most failures (network errors, other API errors) don't carry this
                // structure, so bail out quietly at the first missing piece.
                try {
                    var error = ((MessageResult.UnknownFailure) result).getError();
                    var errorResponse = error != null ? error.getResponse() : null;
                    Diagnostics.logCommandFailure(this.logger, result, localSendData, errorResponse);
                    if (errorResponse == null) return;
                    var skemaError = this.errorResponseErrorField.get(errorResponse);
                    if (skemaError == null) return;
                    var subErrors = (Map<String, Error.SkemaError>) skemaErrorSubErrorsField.get(skemaError);
                    if (subErrors == null || subErrors.get("data") == null) return;
                    var dataErrors = (List<Error.SkemaErrorItem>) skemaErrorErrorsField.get(subErrors.get("data"));
                    if (dataErrors == null) return;

                    for (var dataError: dataErrors) {
                        var errorCode = (String) this.skemaErrorItemCodeField.get(dataError);
                        if ("INTERACTION_APPLICATION_COMMAND_INVALID_VERSION".equals(errorCode)) {
                            var guildId = localSendData.component3();
                            if (guildId != null) {
                                this.invalidateApplicationIndex(new ApplicationIndexSourceGuild(guildId));
                            } else {
                                this.invalidateApplicationIndex(new ApplicationIndexSourceDm(localSendData.component2()));
                            }
                            // The outdated command may come from a user-installed app as well
                            this.invalidateApplicationIndex(new ApplicationIndexSourceUser());

                            var errorMessage = (String) this.skemaErrorItemMessageField.get(dataError);
                            if (errorMessage != null) {
                                Utils.showToast(errorMessage);
                            }

                            break;
                        }
                    }
                } catch (Throwable e) {
                    this.logger.error("Failed to handle application command error", e);
                }
            })
        );

        GatewayAPI.onEvent("GUILD_APPLICATION_COMMAND_INDEX_UPDATE", ApiGuildApplicationCommandIndexUpdate.class, guildApplicationCommandIndexUpdate -> {
            this.invalidateApplicationIndex(new ApplicationIndexSourceGuild(guildApplicationCommandIndexUpdate.guildId));
            return null;
        });
    }

    private void passCommandData(StoreApplicationCommands storeApplicationCommands, Optional<ApplicationIndexSource> applicationIndexSource, RequestSource requestSource) throws Exception {
        // Guild/DM index first: it takes priority over the user index when merging
        var applicationIndexes = new ArrayList<ApplicationIndex>();
        if (applicationIndexSource.isPresent()) {
            applicationIndexes.add(this.requestApplicationIndex(applicationIndexSource.get()));
        }
        applicationIndexes.add(this.requestApplicationIndex(new ApplicationIndexSourceUser()));
        var applicationIndex = new ApplicationIndex(applicationIndexes);
        applicationIndex
            .applicationCommands
            .entrySet()
            .removeIf(applicationCommand -> applicationCommand.getValue().type != RemoteApplicationCommand.TYPE_CHAT_INPUT);
        applicationIndex.populateCommandCounts(this.applicationCommandCountField);

        var applications = new ArrayList<Application>(applicationIndex.applications.values());
        applications.sort(Comparator.comparing(Application::getName, Comparator.nullsLast(String.CASE_INSENSITIVE_ORDER)));
        applications.add(((BuiltInCommandsProvider) this.storeApplicationCommandsBuiltInCommandsProviderField.get(storeApplicationCommands)).getBuiltInApplication());
        this.handleGuildApplicationsUpdateMethod.invoke(storeApplicationCommands, applications);

        switch (requestSource) {
            case BROWSE:
                this.handleDiscoverCommandsUpdateMethod.invoke(storeApplicationCommands, new ArrayList<>(applicationIndex.applicationCommands.values()));
                break;

            case QUERY:
                this.handleQueryCommandsUpdateMethod.invoke(storeApplicationCommands, new ArrayList<>(applicationIndex.applicationCommands.values()));
                break;
        }
    }

    /**
     * Returns the application index for a source, fetching it if it isn't cached or is stale.
     * Blocks on network, so only call it off the main thread (the store dispatcher).
     */
    private ApplicationIndex requestApplicationIndex(ApplicationIndexSource source) throws Exception {
        var key = source.getEndpoint();
        var cached = this.applicationIndexCache.getFresh(key);
        if (cached.isPresent()) {
            return cached.get();
        }

        // One request per index at a time; concurrent callers reuse its result
        synchronized (this.applicationIndexCache.lockFor(key)) {
            cached = this.applicationIndexCache.getFresh(key);
            if (cached.isPresent()) {
                return cached.get();
            }

            var generation = this.applicationIndexCache.generation(key);
            var json = Http.Request.newDiscordRNRequest(key)
                .execute()
                .text();
            var applicationIndex = GsonUtils.fromJson(GsonUtils.getGsonRestApi(), json, ApiApplicationIndex.class)
                .toModel();
            this.applicationIndexCache.put(key, applicationIndex, generation);
            Diagnostics.logIndexShape(this.logger, key, json);
            return applicationIndex;
        }
    }

    private void invalidateApplicationIndex(ApplicationIndexSource source) {
        this.applicationIndexCache.invalidate(source.getEndpoint());
    }

    private static Optional<ApplicationIndexSource> applicationIndexSourceFromContext(long guildId, StoreChannelsSelected storeChannelsSelected) {
        Optional<ApplicationIndexSource> applicationIndexSource = Optional.empty();
        // guildId being 0 means this is a DM or a DM group
        if (guildId != 0) {
            applicationIndexSource = Optional.of(new ApplicationIndexSourceGuild(guildId));
        } else {
            // Only create a DM index source for bots
            var channel = storeChannelsSelected.getSelectedChannel();
            var channelType = channel != null ? channel.D() : -1;
            var recipients = channel != null ? channel.z() : null;
            if (channelType == Channel.DM && recipients != null && !recipients.isEmpty()) {
                var user = recipients.get(0);
                var userIsBot = Optional.ofNullable(user.e())
                    .orElse(false);
                if (userIsBot) {
                    var channelId = channel.k();
                    applicationIndexSource = Optional.of(new ApplicationIndexSourceDm(channelId));
                }
            }
        }

        return applicationIndexSource;
    }
}
