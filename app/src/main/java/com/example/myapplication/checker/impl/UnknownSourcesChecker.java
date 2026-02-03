package com.example.myapplication.checker.impl;

import android.content.Context;
import android.content.pm.PackageManager;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;

public class UnknownSourcesChecker implements IChecker {

    @Override public String id() { return "unknown_sources"; }
    @Override public String title() { return "Install unknown apps"; }

    @Override
    public CheckerResult run(Context context) {
        try {
            PackageManager pm = context.getPackageManager();
            boolean allowed = pm.canRequestPackageInstalls(); // Android 8+

            if (allowed) {
                return CheckerResult.fail("Allowed", "Разрешена установка из неизвестных источников (risk signal).");
            }
            return CheckerResult.pass("Not allowed", "Установка из неизвестных источников запрещена.");
        } catch (Throwable t) {
            return CheckerResult.unknown("Unsupported", "API недоступен/ошибка чтения.");
        }
    }
}
