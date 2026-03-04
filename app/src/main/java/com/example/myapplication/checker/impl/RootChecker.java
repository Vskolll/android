package com.example.myapplication.checker.impl;

import android.content.Context;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;
import com.example.myapplication.checker.util.PackageCheck;
import com.example.myapplication.checker.util.SystemProp;
import com.example.myapplication.checker.util.ProcScan;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

public class RootChecker implements IChecker {

    @Override
    public String id() {
        return "root";
    }

    @Override
    public String title() {
        return "Root";
    }

    @Override
    public CheckerResult run(Context context) {
        List<String> hits = new ArrayList<>();
        List<String> details = new ArrayList<>();

        boolean suPath = existsAny(
                "/system/bin/su",
                "/system/xbin/su",
                "/sbin/su",
                "/system/su",
                "/system/bin/.ext/su",
                "/system/usr/we-need-root/su",
                "/system/app/Superuser.apk",
                "/system/app/SuperSU.apk",
                "/system/app/Magisk.apk",
                "/sbin/.magisk",
                "/data/adb/magisk",
                "/data/adb/zygisk",
                "/data/adb/modules",
                "/data/adb/modules_update",
                "/data/adb/service.d",
                "/metadata/magisk",
                "/su/bin/su",
                "/system/bin/supersu",
                "/system/xbin/daemonsu",
                "/system/bin/daemonsu",
                "/cache/su",
                "/data/local/su",
                "/data/local/xbin/su",
                "/data/local/bin/su"
        );
        details.add("su_path=" + suPath);
        if (suPath) hits.add("su-path");

        boolean rwSystem = isRwMount("/system") || isRwMount("/vendor") || isRwMount("/product");
        details.add("rw_mount(system/vendor/product)=" + rwSystem);
        if (rwSystem) hits.add("rw-mount");

        String buildTags = SystemProp.firstNonEmpty(android.os.Build.TAGS, SystemProp.get("ro.build.tags"));
        boolean testKeys = buildTags != null && buildTags.contains("test-keys");
        details.add("build_tags=" + (buildTags == null ? "" : buildTags));
        if (testKeys) hits.add("test-keys");

        String roSecure = SystemProp.get("ro.secure");
        String roDebuggable = SystemProp.get("ro.debuggable");
        details.add("ro.secure=" + roSecure);
        details.add("ro.debuggable=" + roDebuggable);
        if ("0".equals(roSecure)) hits.add("ro.secure=0");
        if ("1".equals(roDebuggable)) hits.add("ro.debuggable=1");

        String[] magiskProps = new String[] {
                "ro.magisk.version",
                "ro.magisk.version_code",
                "persist.magisk.hide",
                "persist.magisk.hide_props",
                "persist.magisk.hide_sulist",
                "persist.magisk.sulist",
                "persist.magisk.magiskhide"
        };
        boolean magiskPropHit = false;
        for (String k : magiskProps) {
            String v = SystemProp.get(k);
            if (v != null && !v.trim().isEmpty()) {
                details.add(k + "=" + v.trim());
                magiskPropHit = true;
            }
        }
        if (magiskPropHit) hits.add("magisk-props");

        boolean magiskPkg = PackageCheck.isInstalled(context, "com.topjohnwu.magisk")
                || PackageCheck.isInstalled(context, "com.topjohnwu.magisk.beta")
                || PackageCheck.isInstalled(context, "io.github.vvb2060.magisk");
        boolean supersuPkg = PackageCheck.isInstalled(context, "eu.chainfire.supersu")
                || PackageCheck.isInstalled(context, "com.koushikdutta.superuser")
                || PackageCheck.isInstalled(context, "com.noshufou.android.su")
                || PackageCheck.isInstalled(context, "com.thirdparty.superuser")
                || PackageCheck.isInstalled(context, "com.yellowes.su");
        boolean kingRootPkg = PackageCheck.isInstalled(context, "com.kingroot.kinguser")
                || PackageCheck.isInstalled(context, "com.kingo.root")
                || PackageCheck.isInstalled(context, "com.koushikdutta.rommanager");
        boolean rootCloakPkg = PackageCheck.isInstalled(context, "com.devadvance.rootcloak");
        details.add("pkg_magisk=" + magiskPkg);
        details.add("pkg_supersu=" + supersuPkg);
        details.add("pkg_kingroot=" + kingRootPkg);
        details.add("pkg_rootcloak=" + rootCloakPkg);
        if (magiskPkg || supersuPkg || kingRootPkg) hits.add("root-package");

        boolean busybox = existsAny(
                "/system/xbin/busybox",
                "/system/bin/busybox",
                "/sbin/busybox",
                "/data/local/busybox",
                "/data/local/xbin/busybox"
        );
        details.add("busybox=" + busybox);
        if (busybox) hits.add("busybox");

        boolean mapHit = ProcScan.selfMapsContains(
                "magisk", "zygisk", "xposed", "lsposed", "edxp", "substrate", "libhook"
        );
        details.add("maps(hooks)=" + mapHit);
        if (mapHit) hits.add("maps");

        boolean socketHit = ProcScan.fileContains("/proc/net/unix", "magisk", "magiskd", "zygisk");
        details.add("unix_sockets=" + socketHit);
        if (socketHit) hits.add("unix-socket");

        if (!hits.isEmpty()) {
            boolean strong = suPath || magiskPkg || supersuPkg || kingRootPkg || socketHit;
            StringBuilder body = new StringBuilder();
            body.append("Обнаружены признаки root: ");
            body.append(join(hits, ", "));
            body.append(".\n\nСигналы:\n");
            for (String d : details) {
                body.append("• ").append(d).append("\n");
            }
            return strong
                    ? CheckerResult.fail("Root обнаружен", body.toString().trim())
                    : CheckerResult.warn("Подозрительные признаки", body.toString().trim());
        }

        return CheckerResult.pass(
                "Root не обнаружен",
                "Явных признаков root не найдено.\n\nСигналы:\n• " + join(details, "\n• ")
        );
    }

    private boolean existsAny(String... paths) {
        for (String p : paths) {
            try {
                if (new File(p).exists()) return true;
            } catch (Throwable ignored) {}
        }
        return false;
    }

    private boolean isRwMount(String mountPoint) {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/mounts"));
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(" ");
                if (parts.length < 4) continue;
                String mp = parts[1];
                String opts = parts[3];
                if (mountPoint.equals(mp) && opts.contains("rw")) return true;
            }
        } catch (Throwable ignored) {
        } finally {
            try { if (br != null) br.close(); } catch (Throwable ignored) {}
        }
        return false;
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
