package com.example.myapplication.checker.impl;

import android.content.Context;
import android.provider.Settings;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;

public class AdbEnabledChecker implements IChecker {

    @Override public String id() { return "adb"; }
    @Override public String title() { return "ADB / USB debugging"; }

    @Override
    public CheckerResult run(Context context) {
        try {
            int adb = Settings.Global.getInt(
                    context.getContentResolver(),
                    Settings.Global.ADB_ENABLED,
                    0
            );

            if (adb == 1) {
                return CheckerResult.fail("Enabled", "USB debugging включён (risk signal).");
            }
            return CheckerResult.pass("Disabled", "USB debugging выключён.");
        } catch (Throwable t) {
            return CheckerResult.unknown("No access", "Не удалось прочитать ADB_ENABLED.");
        }
    }
}
