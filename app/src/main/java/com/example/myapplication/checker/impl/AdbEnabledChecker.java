package com.example.myapplication.checker.impl;

import android.content.Context;
import android.provider.Settings;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;

public class AdbEnabledChecker implements IChecker {

    @Override public String id() { return "adb"; }
    @Override public String title() { return "USB‑отладка (ADB)"; }

    @Override
    public CheckerResult run(Context context) {
        if (context == null) {
            return CheckerResult.unknown("No context", "Context недоступен — не удалось прочитать ADB_ENABLED.");
        }

        int adb = -1;
        String source = "";

        try {
            adb = Settings.Global.getInt(
                    context.getContentResolver(),
                    Settings.Global.ADB_ENABLED,
                    0
            );
            source = "Settings.Global.ADB_ENABLED";
        } catch (Throwable ignored) {
        }

        if (source.isEmpty()) {
            try {
                adb = Settings.Secure.getInt(
                        context.getContentResolver(),
                        Settings.Secure.ADB_ENABLED,
                        0
                );
                source = "Settings.Secure.ADB_ENABLED";
            } catch (Throwable ignored) {
            }
        }

        if (source.isEmpty()) {
            return CheckerResult.unknown("No access", "Не удалось прочитать ADB_ENABLED.");
        }

        String details = "adb_enabled=" + adb + "  source=" + source;

        if (adb == 1) {
            return CheckerResult.fail("Включено", "USB‑отладка активна.\n\n" + details);
        }
        return CheckerResult.pass("Выключено", "USB‑отладка отключена.\n\n" + details);
    }
}
