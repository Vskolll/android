package com.example.myapplication.checker.impl;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;

public class UnknownSourcesChecker implements IChecker {

    @Override public String id() { return "unknown_sources"; }
    @Override public String title() { return "Неизвестные источники"; }

    @Override
    public CheckerResult run(Context context) {
        if (context == null) {
            return CheckerResult.unknown("No context", "Context недоступен — не удалось проверить настройку.");
        }

        String details = "";
        boolean allowed = false;
        boolean known = false;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            try {
                PackageManager pm = context.getPackageManager();
                allowed = pm != null && pm.canRequestPackageInstalls();
                known = true;
                details = "method=PackageManager.canRequestPackageInstalls";
            } catch (Throwable ignored) {
            }
        }

        if (!known) {
            try {
                int v = Settings.Secure.getInt(
                        context.getContentResolver(),
                        Settings.Secure.INSTALL_NON_MARKET_APPS,
                        0
                );
                allowed = (v == 1);
                known = true;
                details = "method=Settings.Secure.INSTALL_NON_MARKET_APPS value=" + v;
            } catch (Throwable ignored) {
            }
        }

        if (!known) {
            return CheckerResult.unknown("Unsupported", "API недоступен/ошибка чтения.");
        }

        if (allowed) {
            return CheckerResult.fail("Разрешено", "Разрешена установка приложений из неизвестных источников.\n\n" + details);
        }
        return CheckerResult.pass("Запрещено", "Установка приложений из неизвестных источников запрещена.\n\n" + details);
    }
}
