package com.example.myapplication.checker.impl;


import android.content.Context;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;
import com.example.myapplication.checker.util.SystemProp;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

public class SelinuxChecker implements IChecker {

    @Override public String id() { return "selinux"; }
    @Override public String title() { return "SELinux"; }

    @Override
    public CheckerResult run(Context context) {
        String source = "";
        String mode = "";

        // 1) android.os.SELinux via reflection (class hidden in SDK)
        String refl = readSelinuxViaReflection();
        if (!refl.isEmpty()) {
            mode = refl;
            source = "android.os.SELinux(reflect)";
        }

        // 2) getprop ro.build.selinux
        if (source.isEmpty()) {
            String prop = SystemProp.get("ro.build.selinux");
            if (!prop.isEmpty()) {
                mode = prop;
                source = "prop(ro.build.selinux)";
            }
        }

        // 3) /sys/fs/selinux/enforce
        if (source.isEmpty()) {
            String v = readFirstLine("/sys/fs/selinux/enforce");
            if (!v.isEmpty()) {
                if ("1".equals(v.trim())) mode = "enforcing";
                else if ("0".equals(v.trim())) mode = "permissive";
                else mode = v.trim();
                source = "/sys/fs/selinux/enforce";
            }
        }

        // 4) getenforce
        if (source.isEmpty()) {
            String v = readFirstLine("/sys/fs/selinux/status");
            if (!v.isEmpty()) {
                mode = v.trim();
                source = "/sys/fs/selinux/status";
            }
        }

        if (source.isEmpty()) {
            return CheckerResult.unknown("No access", "Не удалось определить SELinux режим.");
        }

        String details = "selinux=" + mode + "  source=" + source;

        String m = mode.toLowerCase();
        if (m.contains("permissive") || m.contains("disabled")) {
            return CheckerResult.warn(
                    "SELinux не enforcing",
                    "SELinux работает не в enforcing режиме.\n\n" + details
            );
        }

        if (m.contains("enforcing")) {
            return CheckerResult.pass(
                    "SELinux enforcing",
                    "SELinux в режиме enforcing.\n\n" + details
            );
        }

        return CheckerResult.warn(
                "Неизвестный режим",
                "Нестандартный статус SELinux: " + mode + ".\n\n" + details
        );
    }

    private String readSelinuxViaReflection() {
        try {
            Class<?> cls = Class.forName("android.os.SELinux");
            Boolean enabled = (Boolean) cls.getMethod("isSELinuxEnabled").invoke(null);
            if (enabled != null && !enabled) return "disabled";
            Boolean enforced = (Boolean) cls.getMethod("isSELinuxEnforced").invoke(null);
            if (enforced != null) return enforced ? "enforcing" : "permissive";
        } catch (Throwable ignored) {
        }
        return "";
    }

    private String readFirstLine(String path) {
        File f = new File(path);
        if (!f.canRead()) return "";
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(f));
            String line = br.readLine();
            return line == null ? "" : line.trim();
        } catch (Throwable ignored) {
            return "";
        } finally {
            try { if (br != null) br.close(); } catch (Throwable ignored) {}
        }
    }
}
