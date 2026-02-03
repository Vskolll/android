package com.example.myapplication.checker.impl;


import android.content.Context;
import android.provider.Settings;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;

public class DeveloperOptionsChecker implements IChecker {

    @Override public String id() { return "dev_options"; }
    @Override public String title() { return "Developer options"; }

    @Override
    public CheckerResult run(Context context) {
        try {
            int enabled = Settings.Global.getInt(
                    context.getContentResolver(),
                    Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
                    0
            );

            if (enabled == 1) {
                return CheckerResult.fail("Enabled", "Опции разработчика включены (risk signal).");
            }
            return CheckerResult.pass("Disabled", "Опции разработчика выключены.");
        } catch (Throwable t) {
            return CheckerResult.unknown("No access", "Не удалось прочитать DEVELOPMENT_SETTINGS_ENABLED.");
        }
    }
}
