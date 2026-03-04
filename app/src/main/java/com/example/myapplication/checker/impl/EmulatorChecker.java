package com.example.myapplication.checker.impl;

import android.content.Context;
import android.os.Build;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;
import com.example.myapplication.checker.util.SystemProp;

import java.util.ArrayList;
import java.util.List;

public class EmulatorChecker implements IChecker {

    @Override
    public String id() {
        return "emulator";
    }

    @Override
    public String title() {
        return "Эмулятор";
    }

    @Override
    public CheckerResult run(Context context) {
        List<String> hits = new ArrayList<>();
        List<String> details = new ArrayList<>();

        String fingerprint = safeLower(Build.FINGERPRINT);
        String model = safeLower(Build.MODEL);
        String manufacturer = safeLower(Build.MANUFACTURER);
        String brand = safeLower(Build.BRAND);
        String device = safeLower(Build.DEVICE);
        String product = safeLower(Build.PRODUCT);
        String hardware = safeLower(Build.HARDWARE);
        String bootloader = safeLower(Build.BOOTLOADER);
        String board = safeLower(Build.BOARD);
        String host = safeLower(Build.HOST);
        String modelProp = safeLower(SystemProp.get("ro.product.model"));
        String deviceProp = safeLower(SystemProp.get("ro.product.device"));
        String manufProp = safeLower(SystemProp.get("ro.product.manufacturer"));
        String hardwareProp = safeLower(SystemProp.get("ro.hardware"));

        details.add("fingerprint=" + fingerprint);
        details.add("model=" + model);
        details.add("manufacturer=" + manufacturer);
        details.add("brand=" + brand);
        details.add("device=" + device);
        details.add("product=" + product);
        details.add("hardware=" + hardware);
        details.add("bootloader=" + bootloader);
        details.add("board=" + board);
        details.add("host=" + host);
        details.add("ro.product.model=" + modelProp);
        details.add("ro.product.device=" + deviceProp);
        details.add("ro.product.manufacturer=" + manufProp);
        details.add("ro.hardware=" + hardwareProp);

        if (containsAny(fingerprint, "generic", "unknown", "emulator", "sdk_gphone", "google_sdk", "vbox", "test-keys")) {
            hits.add("fingerprint");
        }
        if (containsAny(model, "emulator", "android sdk built for", "sdk_gphone", "google_sdk")) {
            hits.add("model");
        }
        if (containsAny(manufacturer, "genymotion", "unknown", "andy", "nox", "bluestacks")) {
            hits.add("manufacturer");
        }
        if (containsAny(brand, "generic") || containsAny(device, "generic", "emulator", "sdk_gphone")) {
            hits.add("brand/device");
        }
        if (containsAny(product, "sdk", "emulator", "google_sdk", "vbox", "sdk_gphone", "simulator")) {
            hits.add("product");
        }
        if (containsAny(hardware, "goldfish", "ranchu", "vbox", "qemu", "nox", "ttvm_x86")) {
            hits.add("hardware");
        }
        if (containsAny(modelProp, "sdk", "emulator", "google_sdk", "sdk_gphone")) {
            hits.add("ro.product.model");
        }
        if (containsAny(deviceProp, "generic", "emulator", "sdk_gphone")) {
            hits.add("ro.product.device");
        }
        if (containsAny(manufProp, "genymotion", "unknown", "nox", "bluestacks")) {
            hits.add("ro.product.manufacturer");
        }
        if (containsAny(hardwareProp, "goldfish", "ranchu", "vbox", "qemu")) {
            hits.add("ro.hardware");
        }
        if (containsAny(bootloader, "qemu")) {
            hits.add("bootloader");
        }
        if (containsAny(board, "goldfish", "ranchu", "vbox")) {
            hits.add("board");
        }
        if (containsAny(host, "buildhost", "android-build")) {
            hits.add("host");
        }

        String propQemu = safeLower(SystemProp.get("ro.kernel.qemu"));
        String propQemu2 = safeLower(SystemProp.get("ro.boot.qemu"));
        boolean qemu = "1".equals(propQemu) || "true".equals(propQemu)
                || "1".equals(propQemu2) || "true".equals(propQemu2);
        details.add("ro.kernel.qemu=" + propQemu);
        details.add("ro.boot.qemu=" + propQemu2);
        if (qemu) hits.add("qemu-prop");

        if (!hits.isEmpty()) {
            boolean strong = qemu || hits.size() >= 3;
            StringBuilder body = new StringBuilder();
            body.append("Обнаружены признаки эмулятора: ").append(join(hits, ", ")).append(".\n\nСигналы:\n• ");
            body.append(join(details, "\n• "));
            return strong
                    ? CheckerResult.fail("Эмулятор", body.toString())
                    : CheckerResult.warn("Возможный эмулятор", body.toString());
        }

        return CheckerResult.pass(
                "Похоже на физическое устройство",
                "Явных признаков эмулятора не найдено.\n\nСигналы:\n• " + join(details, "\n• ")
        );
    }

    private static boolean containsAny(String s, String... needles) {
        if (s == null) return false;
        for (String n : needles) {
            if (n == null) continue;
            if (s.contains(n.toLowerCase())) return true;
        }
        return false;
    }

    private static String safeLower(String s) {
        return s == null ? "" : s.toLowerCase();
    }

    private static String join(List<String> xs, String sep) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < xs.size(); i++) {
            if (i > 0) sb.append(sep);
            sb.append(xs.get(i));
        }
        return sb.toString();
    }
}
