package com.example.myapplication.checker.impl;

import android.content.Context;

import java.io.File;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;
import com.example.myapplication.checker.util.PackageCheck;
import com.example.myapplication.checker.util.ProcScan;

public class MagiskFlagChecker implements IChecker {

    @Override public String id() { return "magisk"; }

    @Override public String title() { return "Magisk artifacts"; }

    @Override
    public CheckerResult run(Context context) {
        // 1) Пакет Magisk (может быть скрыт/переименован, но как флаг — полезно)
        boolean magiskPkg = PackageCheck.isInstalled(context, "com.topjohnwu.magisk");

        // 2) Файловые артефакты (часть может быть недоступна без root — best-effort)
        String[] paths = new String[] {
                "/sbin/magisk",
                "/sbin/.magisk",
                "/data/adb/magisk",
                "/data/adb/modules",
                "/init.magisk.rc",
                "/system/etc/init/magisk.rc",
                "/cache/magisk.log"
        };
        String hitPath = firstExisting(paths);

        // 3) Сигнатуры в proc (иногда встречается “magisk” в mount/maps) — best-effort
        boolean magiskInProc = ProcScan.fileContains("/proc/self/mounts", "magisk")
                || ProcScan.selfMapsContains("magisk");

        if (magiskPkg || hitPath != null || magiskInProc) {
            String details =
                    "pkg(com.topjohnwu.magisk)=" + magiskPkg +
                            "\nfileHit=" + (hitPath == null ? "none" : hitPath) +
                            "\nprocHint=" + magiskInProc;

            return CheckerResult.fail(
                    "Magisk suspected",
                    "Найдены признаки Magisk (best-effort).\n\n" + details
            );
        }

        return CheckerResult.pass(
                "No Magisk artifacts",
                "Явных признаков Magisk не найдено (учти: Magisk Hide/ренейм может маскировать)."
        );
    }

    private String firstExisting(String[] paths) {
        for (String p : paths) {
            try {
                if (new File(p).exists()) return p;
            } catch (Throwable ignored) {}
        }
        return null;
    }
}
