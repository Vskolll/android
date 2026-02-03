package com.example.myapplication.checker.impl;

import android.content.Context;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;
import com.example.myapplication.checker.util.SystemProp;

public class BootloaderVerifiedBootChecker implements IChecker {

    @Override public String id() { return "bootloader_vb"; }

    @Override public String title() { return "Bootloader / Verified Boot"; }

    @Override
    public CheckerResult run(Context context) {
        // Часто встречающиеся проперти (разные вендоры/версии)
        String flashLocked = SystemProp.firstNonEmpty(
                SystemProp.get("ro.boot.flash.locked"),
                SystemProp.get("ro.boot.flashlocked"),
                SystemProp.get("ro.boot.locked")
        ); // "1"/"0" или "true"/"false"

        String vbState = SystemProp.firstNonEmpty(
                SystemProp.get("ro.boot.vbmeta.device_state"),
                SystemProp.get("ro.boot.avb.device_state")
        ); // "locked"/"unlocked"

        String verified = SystemProp.firstNonEmpty(
                SystemProp.get("ro.boot.verifiedbootstate"),
                SystemProp.get("ro.boot.verifiedboot.state")
        ); // "green"/"yellow"/"orange"/"red"

        String verityMode = SystemProp.firstNonEmpty(
                SystemProp.get("ro.boot.veritymode"),
                SystemProp.get("ro.boot.dmverity")
        );

        String warrantyBit = SystemProp.firstNonEmpty(
                SystemProp.get("ro.boot.warranty_bit"),
                SystemProp.get("ro.warranty_bit")
        );

        String desc =
                "ro.boot.flash.locked=" + flashLocked +
                        "\nro.boot.vbmeta.device_state=" + vbState +
                        "\nro.boot.verifiedbootstate=" + verified +
                        "\nro.boot.veritymode/ro.boot.dmverity=" + verityMode +
                        "\nro.boot.warranty_bit/ro.warranty_bit=" + warrantyBit;

        boolean explicitUnlocked =
                SystemProp.isFalseish(flashLocked) ||
                        "unlocked".equalsIgnoreCase(vbState);

        if (explicitUnlocked) {
            return CheckerResult.fail(
                    "Bootloader UNLOCKED",
                    "Устройство в состоянии unlocked/flash.locked=0. AVB/Verified Boot гарантии отсутствуют.\n\n" + desc
            );
        }

        // verifiedbootstate интерпретация
        if ("green".equalsIgnoreCase(verified)) {
            return CheckerResult.pass(
                    "Verified Boot GREEN",
                    "Bootloader выглядит залоченным, verifiedbootstate=green.\n\n" + desc
            );
        }

        if ("orange".equalsIgnoreCase(verified) || "red".equalsIgnoreCase(verified)) {
            return CheckerResult.fail(
                    "Verified Boot not green",
                    "verifiedbootstate=" + verified +
                            " — часто признак кастома/модификаций или проблем цепочки доверия.\n\n" + desc
            );
        }

        if ("yellow".equalsIgnoreCase(verified)) {
            return CheckerResult.fail(
                    "Verified Boot YELLOW",
                    "verifiedbootstate=yellow — состояние не является идеальным green.\n\n" + desc
            );
        }

        // Если verified пустой/неожиданный — пытаемся дать “мягкую” диагностику по verity/warranty
        if (SystemProp.isTrueish(warrantyBit) || "1".equals(warrantyBit)) {
            return CheckerResult.fail(
                    "Warranty bit set",
                    "warranty_bit=1 — часто означает вмешательство (зависит от вендора).\n\n" + desc
            );
        }

        return CheckerResult.unknown(
                "Не удалось однозначно определить",
                "Проперти пустые/недоступны или устройство не отдаёт нужные значения.\n\n" + desc
        );
    }
}
