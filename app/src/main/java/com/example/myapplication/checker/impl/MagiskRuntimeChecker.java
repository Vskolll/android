package com.example.myapplication.checker.impl;

import android.content.Context;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;
import com.example.myapplication.checker.util.ProcScan;
import com.example.myapplication.checker.util.SystemProp;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class MagiskRuntimeChecker implements IChecker {

    @Override public String id() { return "magisk_runtime"; }

    @Override public String title() { return "Magisk (runtime)"; }

    @Override
    public CheckerResult run(Context context) {
        List<String> hits = new ArrayList<>();
        List<String> details = new ArrayList<>();

        boolean fileHit = existsAny(
                "/sbin/magisk",
                "/sbin/.magisk",
                "/data/adb/magisk",
                "/data/adb/zygisk",
                "/data/adb/modules",
                "/data/adb/modules_update",
                "/data/adb/magisk.db",
                "/data/adb/service.d",
                "/data/adb/post-fs-data.d",
                "/metadata/magisk",
                "/dev/socket/magiskd"
        );
        details.add("files(magisk)=" + fileHit);
        if (fileHit) hits.add("files");

        // unix sockets
        boolean sockHit = ProcScan.fileContains("/proc/net/unix", "magisk", "magiskd", "zygisk");
        details.add("unix_sockets(magisk/zygisk)=" + sockHit);
        if (sockHit) hits.add("socket");

        // mounts (avoid generic "overlay" false positives)
        boolean mountHit = ProcScan.fileContains("/proc/self/mounts", "magisk", "zygisk");
        details.add("mounts(magisk/zygisk)=" + mountHit);
        if (mountHit) hits.add("mounts");

        // cmdline scan
        boolean procHit = scanProcCmdlines("magisk", "magiskd", "zygisk");
        details.add("proc_cmdline(magisk)=" + procHit);
        if (procHit) hits.add("proc");

        // maps scan
        boolean mapsHit = ProcScan.selfMapsContains("magisk", "zygisk");
        details.add("maps(magisk/zygisk)=" + mapsHit);
        if (mapsHit) hits.add("maps");

        // system properties (best-effort)
        List<String> propHits = readMagiskProps();
        if (!propHits.isEmpty()) {
            details.add("magisk_props=" + join(propHits, ", "));
            hits.add("props");
        } else {
            details.add("magisk_props=none");
        }

        if (!hits.isEmpty()) {
            boolean strong = fileHit || sockHit || procHit || mapsHit;
            StringBuilder body = new StringBuilder();
            body.append("Обнаружены признаки Magisk/Zygisk: ").append(join(hits, ", "));
            body.append(".\n\nСигналы:\n• ").append(join(details, "\n• "));
            return strong
                    ? CheckerResult.fail("Magisk активен", body.toString())
                    : CheckerResult.warn("Подозрительные признаки", body.toString());
        }

        return CheckerResult.pass(
                "Magisk/Zygisk не обнаружен",
                "Явных признаков Magisk/Zygisk не найдено.\n\nСигналы:\n• "
                        + join(details, "\n• ")
        );
    }

    private List<String> readMagiskProps() {
        String[] keys = new String[] {
                "ro.magisk.version",
                "ro.magisk.version_code",
                "persist.magisk.hide",
                "persist.magisk.hide_props",
                "persist.magisk.hide_sulist",
                "persist.magisk.sulist",
                "persist.magisk.magiskhide"
        };
        List<String> out = new ArrayList<>();
        for (String k : keys) {
            String v = SystemProp.get(k);
            if (v != null && !v.trim().isEmpty()) {
                out.add(k + "=" + v.trim());
            }
        }
        return out;
    }

    private boolean existsAny(String... paths) {
        for (String p : paths) {
            try {
                if (new File(p).exists()) return true;
            } catch (Throwable ignored) {}
        }
        return false;
    }

    private boolean scanProcCmdlines(String... needles) {
        File proc = new File("/proc");
        File[] entries = proc.listFiles();
        if (entries == null) return false;

        int scanned = 0;
        for (File f : entries) {
            if (scanned > 200) break;
            String name = f.getName();
            if (!isNumeric(name)) continue;

            String cmdline = readFirstLine(new File(f, "cmdline"));
            if (cmdline.isEmpty()) continue;
            scanned++;
            String lower = cmdline.toLowerCase(Locale.US);
            for (String n : needles) {
                if (n != null && lower.contains(n.toLowerCase(Locale.US))) return true;
            }
        }
        return false;
    }

    private boolean isNumeric(String s) {
        if (s == null || s.isEmpty()) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') return false;
        }
        return true;
    }

    private String readFirstLine(File f) {
        if (f == null || !f.canRead()) return "";
        BufferedReader br = null;
        String out = "";
        try {
            br = new BufferedReader(new FileReader(f));
            String line = br.readLine();
            out = (line == null ? "" : line.trim());
        } catch (Throwable ignored) {
            out = "";
        } finally {
            try { if (br != null) br.close(); } catch (Throwable ignored) {}
        }
        return out;
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
