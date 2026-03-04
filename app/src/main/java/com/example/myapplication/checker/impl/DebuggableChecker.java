package com.example.myapplication.checker.impl;


import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;

public class DebuggableChecker implements IChecker {

    @Override
    public String id() {
        return "debuggable";
    }

    @Override
    public String title() {
        return "Debuggable";
    }

    @Override
    public CheckerResult run(Context context) {
        if (context == null) {
            return CheckerResult.unknown(
                    "No context",
                    "Context недоступен — не удалось проверить debuggable flag."
            );
        }

        boolean debuggable = false;
        String source = "";

        try {
            ApplicationInfo ai = context.getApplicationInfo();
            if (ai != null) {
                debuggable = (ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
                source = "ApplicationInfo.flags";
            }
        } catch (Throwable ignored) {
        }

        if (source.isEmpty()) {
            try {
                PackageManager pm = context.getPackageManager();
                if (pm != null) {
                    ApplicationInfo ai = pm.getApplicationInfo(context.getPackageName(), 0);
                    debuggable = (ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
                    source = "PackageManager.getApplicationInfo";
                }
            } catch (Throwable ignored) {
            }
        }

        String details = "debuggable=" + debuggable + "  source=" + (source.isEmpty() ? "unknown" : source);

        if (debuggable) {
            return CheckerResult.fail(
                    "Debuggable",
                    "Приложение собрано с флагом debuggable.\n\n" + details
            );
        }

        return CheckerResult.pass(
                "Not debuggable",
                "Флаг debuggable не установлен.\n\n" + details
        );
    }
}
