package com.example.myapplication.checker.impl;


import android.content.Context;
import android.provider.Settings;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;

public class DeveloperOptionsChecker implements IChecker {

    @Override public String id() { return "dev_options"; }
    @Override public String title() { return "Опции разработчика"; }

    @Override
    public CheckerResult run(Context context) {
        if (context == null) {
            return CheckerResult.unknown("No context", "Context недоступен — не удалось прочитать DEVELOPMENT_SETTINGS_ENABLED.");
        }

        int enabled = -1;
        String source = "";

        try {
            enabled = Settings.Global.getInt(
                    context.getContentResolver(),
                    Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
                    0
            );
            source = "Settings.Global.DEVELOPMENT_SETTINGS_ENABLED";
        } catch (Throwable ignored) {
        }

        if (source.isEmpty()) {
            try {
                enabled = Settings.Secure.getInt(
                        context.getContentResolver(),
                        Settings.Secure.DEVELOPMENT_SETTINGS_ENABLED,
                        0
                );
                source = "Settings.Secure.DEVELOPMENT_SETTINGS_ENABLED";
            } catch (Throwable ignored) {
            }
        }

        if (source.isEmpty()) {
            return CheckerResult.unknown("No access", "Не удалось прочитать DEVELOPMENT_SETTINGS_ENABLED.");
        }

        String details = "developer_options=" + enabled + "  source=" + source;

        if (enabled == 1) {
            return CheckerResult.fail("Включено", "Опции разработчика активны.\n\n" + details);
        }
        return CheckerResult.pass("Выключено", "Опции разработчика отключены.\n\n" + details);
    }
}
