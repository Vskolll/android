package com.example.myapplication.checker.impl;

import android.content.Context;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;
import com.example.myapplication.checker.util.SystemProp;

public class BootModeChecker implements IChecker {

    @Override public String id() { return "boot_mode"; }

    @Override public String title() { return "Boot Mode / Boot Reason"; }

    @Override
    public CheckerResult run(Context context) {
        String bootmode = SystemProp.firstNonEmpty(
                SystemProp.get("ro.bootmode"),
                SystemProp.get("ro.boot.bootmode"),
                SystemProp.get("ro.boot.mode")
        );

        String reason = SystemProp.firstNonEmpty(
                SystemProp.get("ro.boot.bootreason"),
                SystemProp.get("ro.boot.boot_reason"),
                SystemProp.get("sys.boot.reason")
        );

        String safeMode = SystemProp.firstNonEmpty(
                SystemProp.get("ro.boot.safemode"),
                SystemProp.get("persist.sys.safemode")
        );

        String desc =
                "bootmode=" + bootmode +
                        "\nbootreason=" + reason +
                        "\nsafemode=" + safeMode;

        String bm = (bootmode == null ? "" : bootmode.trim().toLowerCase());

        if (!bm.isEmpty()) {
            // “плохие” режимы
            if (bm.contains("recovery") || bm.contains("bootloader") || bm.contains("fastboot")) {
                return CheckerResult.fail(
                        "Non-normal boot mode",
                        "bootmode=" + bootmode + " — устройство загружено не в normal режиме.\n\n" + desc
                );
            }
            if (bm.contains("safe")) {
                return CheckerResult.fail(
                        "Safe mode",
                        "bootmode=" + bootmode + " — safe mode.\n\n" + desc
                );
            }
            // “хорошие”
            if (bm.contains("normal") || bm.equals("unknown") == false) {
                return CheckerResult.pass(
                        "Boot mode looks normal",
                        "bootmode=" + bootmode + "\n\n" + desc
                );
            }
        }

        // fallback по safemode
        if (SystemProp.isTrueish(safeMode)) {
            return CheckerResult.fail(
                    "Safe mode flag",
                    "safemode=1/true.\n\n" + desc
            );
        }

        // если хоть bootreason есть — покажем unknown с инфой
        if ((reason != null && !reason.trim().isEmpty())) {
            return CheckerResult.unknown(
                    "Boot mode unclear",
                    "bootmode пустой/нечитаемый, но есть bootreason.\n\n" + desc
            );
        }

        return CheckerResult.unknown(
                "Boot info not available",
                "Не удалось прочитать bootmode/bootreason.\n\n" + desc
        );
    }
}
