package com.example.myapplication.checker.impl;

import android.content.Context;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;
import com.example.myapplication.checker.util.SystemProp;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class FirmwareIntegrityChecker implements IChecker {

    @Override public String id() { return "fw_integrity"; }

    @Override public String title() { return "Целостность прошивки"; }

    // prop keys
    private static final String[] KEY_VERIFIED_BOOTSTATE = { "ro.boot.verifiedbootstate" };
    private static final String[] KEY_VBMETA_DEVICE_STATE = { "ro.boot.vbmeta.device_state", "ro.boot.device_state" };
    private static final String[] KEY_FLASH_LOCKED = { "ro.boot.flash.locked", "ro.boot.bootloader.locked", "ro.boot.locked" };
    private static final String[] KEY_VERITYMODE = { "ro.boot.veritymode" };
    private static final String[] KEY_AVB_VERSION = { "ro.boot.avb_version" };
    private static final String[] KEY_VBMETA_DIGEST = { "ro.boot.vbmeta.digest" };

    // kernel arg keys
    private static final String[] KERNEL_VERIFIED_BOOTSTATE = { "androidboot.verifiedbootstate" };
    private static final String[] KERNEL_VBMETA_DEVICE_STATE = { "androidboot.vbmeta.device_state", "androidboot.device_state" };
    private static final String[] KERNEL_FLASH_LOCKED = { "androidboot.flash.locked", "androidboot.bootloader.locked", "androidboot.locked" };

    @Override
    public CheckerResult run(Context context) {
        Signal verifiedBootState = firstSignal(KEY_VERIFIED_BOOTSTATE, KERNEL_VERIFIED_BOOTSTATE);
        Signal vbmetaDeviceState = firstSignal(KEY_VBMETA_DEVICE_STATE, KERNEL_VBMETA_DEVICE_STATE);
        Signal flashLocked = firstSignal(KEY_FLASH_LOCKED, KERNEL_FLASH_LOCKED);
        Signal verityMode = firstSignal(KEY_VERITYMODE, new String[0]);
        Signal avbVersion = firstSignal(KEY_AVB_VERSION, new String[0]);
        Signal vbmetaDigest = firstSignal(KEY_VBMETA_DIGEST, new String[0]);

        String vb = safeLower(verifiedBootState.value);
        String lockState = safeLower(vbmetaDeviceState.value);
        String flash = safeLower(flashLocked.value);
        String verity = safeLower(verityMode.value);

        boolean bootRed = "red".equals(vb);
        boolean bootOrange = "orange".equals(vb);
        boolean bootYellow = "yellow".equals(vb);
        boolean bootGreen = "green".equals(vb);

        boolean unlocked = "unlocked".equals(lockState) || SystemProp.isFalseish(flash);
        boolean locked = "locked".equals(lockState) || SystemProp.isTrueish(flash);
        boolean verityDisabled = "disabled".equals(verity) || "logging".equals(verity);

        String details = buildDetails(verifiedBootState, vbmetaDeviceState, flashLocked, verityMode, avbVersion, vbmetaDigest);

        if (bootRed || bootOrange) {
            return CheckerResult.fail(
                    "Нарушена целостность",
                    "Verified Boot = " + vb.toUpperCase(Locale.US) + ".\n\n" + details
            );
        }

        if (unlocked) {
            return CheckerResult.fail(
                    "Загрузчик разблокирован",
                    "Состояние UNLOCKED.\n\n" + details
            );
        }

        if (verityDisabled) {
            return CheckerResult.warn(
                    "Verity отключён",
                    "dm‑verity отключён или работает не в штатном режиме.\n\n" + details
            );
        }

        if (bootYellow) {
            return CheckerResult.warn(
                    "Verified Boot: YELLOW",
                    "Используются кастомные ключи доверия.\n\n" + details
            );
        }

        if (isZeroHash(vbmetaDigest.value)) {
            return CheckerResult.warn(
                    "VBMeta digest пустой",
                    "Хэш VBMeta отсутствует или нулевой.\n\n" + details
            );
        }

        if (bootGreen && locked) {
            return CheckerResult.pass(
                    "Целостность подтверждена",
                    "Verified Boot = GREEN, загрузчик LOCKED.\n\n" + details
            );
        }

        return CheckerResult.unknown(
                "Недостаточно данных",
                "Сигналов недостаточно для однозначного вывода.\n\n" + details
        );
    }

    private static String buildDetails(
            Signal verifiedBootState,
            Signal vbmetaDeviceState,
            Signal flashLocked,
            Signal verityMode,
            Signal avbVersion,
            Signal vbmetaDigest
    ) {
        List<String> lines = new ArrayList<>();
        lines.add("Сигналы (значение • источник):");
        lines.add("• ro.boot.verifiedbootstate = " + valueOrUnknown(verifiedBootState.value) + "  • " + verifiedBootState.source);
        lines.add("• ro.boot.vbmeta.device_state = " + valueOrUnknown(vbmetaDeviceState.value) + "  • " + vbmetaDeviceState.source);
        lines.add("• ro.boot.flash.locked = " + valueOrUnknown(flashLocked.value) + "  • " + flashLocked.source);
        if (!isBlank(verityMode.value)) lines.add("• ro.boot.veritymode = " + verityMode.value.trim() + "  • " + verityMode.source);
        if (!isBlank(avbVersion.value)) lines.add("• ro.boot.avb_version = " + avbVersion.value.trim() + "  • " + avbVersion.source);
        if (!isBlank(vbmetaDigest.value)) lines.add("• ro.boot.vbmeta.digest = " + vbmetaDigest.value.trim() + "  • " + vbmetaDigest.source);
        lines.add("");
        lines.add("Источники: SystemProperties → getprop → /proc/cmdline");
        return join(lines, "\n");
    }

    private static Signal firstSignal(String[] propKeys, String[] androidbootKeys) {
        for (String k : propKeys) {
            String v = SystemProp.get(k);
            if (!isBlank(v)) return new Signal(v.trim(), "prop(" + k + ")");
        }
        for (String k : androidbootKeys) {
            String v = readKernelArg(k);
            if (!isBlank(v)) return new Signal(v.trim(), "kernel(" + k + ")");
        }
        return new Signal("", "not_found");
    }

    private static String readKernelArg(String key) {
        File f = new File("/proc/cmdline");
        if (!f.canRead()) return "";
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(f));
            String line = br.readLine();
            if (line == null || line.trim().isEmpty()) return "";
            String prefix = key + "=";
            String[] parts = line.split(" ");
            for (String p : parts) {
                if (p.startsWith(prefix)) return p.substring(prefix.length()).trim();
            }
            return "";
        } catch (Throwable t) {
            return "";
        } finally {
            try { if (br != null) br.close(); } catch (Throwable ignored) {}
        }
    }

    private static String safeLower(String s) {
        return s == null ? "" : s.trim().toLowerCase(Locale.US);
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    private static String valueOrUnknown(String s) {
        return isBlank(s) ? "unknown" : s.trim();
    }

    private static boolean isZeroHash(String s) {
        if (s == null) return false;
        String t = s.trim();
        if (t.isEmpty()) return true;
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c != '0') return false;
        }
        return true;
    }

    private static String join(List<String> xs, String sep) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < xs.size(); i++) {
            if (i > 0) sb.append(sep);
            sb.append(xs.get(i));
        }
        return sb.toString();
    }

    private static final class Signal {
        final String value;
        final String source;
        Signal(String value, String source) {
            this.value = value == null ? "" : value;
            this.source = source == null ? "unknown" : source;
        }
    }
}
