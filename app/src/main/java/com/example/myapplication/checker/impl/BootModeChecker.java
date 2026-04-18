package com.example.myapplication.checker.impl;

import android.content.Context;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;
import com.example.myapplication.checker.util.SystemProp;

public class BootModeChecker implements IChecker {

    @Override public String id() { return "boot_mode"; }

    @Override public String title() { return "Режим загрузки"; }

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
                SystemProp.get("sys.boot.reason"),
                SystemProp.get("ro.bootreason")
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
        String br = (reason == null ? "" : reason.trim().toLowerCase());

        if (!bm.isEmpty()) {
            // “плохие” режимы
            if (bm.contains("recovery") || bm.contains("bootloader") || bm.contains("fastboot")) {
                return CheckerResult.fail(
                        "Нештатный режим",
                        "bootmode=" + bootmode + ".\n\n" + desc
                );
            }
            if (bm.contains("safe")) {
                return CheckerResult.fail(
                        "Safe mode",
                        "bootmode=" + bootmode + ".\n\n" + desc
                );
            }
            // “хорошие”
            if (bm.contains("normal")) {
                return CheckerResult.pass(
                        "Нормальный режим",
                        "bootmode=" + bootmode + ".\n\n" + desc
                );
            }
            if (bm.equals("reboot")) {
                return CheckerResult.pass(
                        "Обычный режим",
                        "bootmode=reboot часто встречается как vendor-specific значение на штатно загруженной системе.\n\n" + desc
                );
            }
            if (!bm.equals("unknown")) {
                return CheckerResult.warn(
                        "Нестандартный режим",
                        "bootmode=" + bootmode + ".\n\n" + desc
                );
            }
        }

        // fallback по safemode
        if (SystemProp.isTrueish(safeMode)) {
            return CheckerResult.fail(
                    "Safe mode",
                    "safemode=1/true.\n\n" + desc
            );
        }

        // если хоть bootreason есть — покажем warn с инфой
        if (!br.isEmpty()) {
            if (br.contains("recovery") || br.contains("bootloader") || br.contains("fastboot")) {
                return CheckerResult.fail(
                        "Нештатная причина",
                        "bootreason=" + reason + ".\n\n" + desc
                );
            }
            if (br.contains("safe")) {
                return CheckerResult.fail(
                        "Safe mode",
                        "bootreason=" + reason + ".\n\n" + desc
                );
            }
            return CheckerResult.unknown(
                    "Режим не определён",
                    "bootmode пустой, но есть bootreason.\n\n" + desc
            );
        }

        return CheckerResult.unknown(
                "Нет данных",
                "Не удалось прочитать bootmode/bootreason.\n\n" + desc
        );
    }
}
