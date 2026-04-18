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
        List<String> directHits = new ArrayList<>();
        List<String> indirectHits = new ArrayList<>();
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
        if (fileHit) directHits.add("files");

        // unix sockets
        boolean sockHit = ProcScan.fileContains("/proc/net/unix", "magisk", "magiskd", "zygisk");
        details.add("unix_sockets(magisk/zygisk)=" + sockHit);
        if (sockHit) directHits.add("socket");

        // mounts (avoid generic "overlay" false positives)
        boolean mountHit = ProcScan.fileContains("/proc/self/mounts", "magisk", "zygisk");
        details.add("mounts(magisk/zygisk)=" + mountHit);
        if (mountHit) directHits.add("mounts");

        List<String> mountInfoHits = readMountInfoHits();
        details.add("mountinfo_hits=" + (mountInfoHits.isEmpty() ? "none" : join(mountInfoHits, " | ")));
        if (!mountInfoHits.isEmpty()) directHits.add("mountinfo");

        List<String> mountConsistencyHits = readMountConsistencyHits();
        details.add("mount_consistency=" + (mountConsistencyHits.isEmpty() ? "none" : join(mountConsistencyHits, " | ")));
        if (!mountConsistencyHits.isEmpty()) indirectHits.add("mount-consistency");

        // cmdline scan
        boolean procHit = scanProcCmdlines("magisk", "magiskd", "zygisk");
        details.add("proc_cmdline(magisk)=" + procHit);
        if (procHit) directHits.add("proc");

        // maps scan
        boolean mapsHit = ProcScan.selfMapsContains("magisk", "zygisk");
        details.add("maps(magisk/zygisk)=" + mapsHit);
        if (mapsHit) directHits.add("maps");

        // system properties (best-effort)
        List<String> propHits = readMagiskProps();
        if (!propHits.isEmpty()) {
            details.add("magisk_props=" + join(propHits, ", "));
            directHits.add("props");
        } else {
            details.add("magisk_props=none");
        }

        List<String> bootConsistencyHits = readBootConsistencyHits();
        details.add("boot_consistency=" + (bootConsistencyHits.isEmpty() ? "none" : join(bootConsistencyHits, " | ")));
        if (!bootConsistencyHits.isEmpty()) indirectHits.add("boot-consistency");

        List<String> stringHits = readStringConsistencyHits();
        details.add("string_consistency=" + (stringHits.isEmpty() ? "none" : join(stringHits, ", ")));
        if (!stringHits.isEmpty()) indirectHits.add("string-consistency");

        int indirectScore = indirectHits.size();
        boolean directDetected = !directHits.isEmpty();
        boolean strongIndirect = indirectScore >= 2;
        boolean weakIndirect = indirectScore == 1;

        details.add("direct_hits=" + (directHits.isEmpty() ? "none" : join(directHits, ", ")));
        details.add("indirect_hits=" + (indirectHits.isEmpty() ? "none" : join(indirectHits, ", ")));
        details.add("indirect_score=" + indirectScore);

        if (directDetected || strongIndirect || weakIndirect) {
            StringBuilder body = new StringBuilder();
            body.append("Обнаружены признаки Magisk/Zygisk: ")
                    .append(join(combineHits(directHits, indirectHits), ", "));
            body.append(".\n\nСигналы:\n• ").append(join(details, "\n• "));
            return (directDetected || strongIndirect)
                    ? CheckerResult.fail("Magisk активен", body.toString())
                    : CheckerResult.warn("Косвенные признаки", body.toString());
        }

        return CheckerResult.pass(
                "Magisk/Zygisk не обнаружен",
                "Явных признаков Magisk/Zygisk не найдено.\n\nСигналы:\n• "
                        + join(details, "\n• ")
        );
    }

    private List<String> combineHits(List<String> a, List<String> b) {
        List<String> out = new ArrayList<>();
        if (a != null) out.addAll(a);
        if (b != null) out.addAll(b);
        return out;
    }

    private List<String> readMountInfoHits() {
        return readMountInfoFiltered(true);
    }

    private List<String> readMountConsistencyHits() {
        return readMountInfoFiltered(false);
    }

    private List<String> readMountInfoFiltered(boolean direct) {
        List<String> hits = new ArrayList<>();
        File f = new File("/proc/self/mountinfo");
        if (!f.canRead()) return hits;

        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(f));
            String line;
            while ((line = br.readLine()) != null) {
                String lower = line.toLowerCase(Locale.US);
                if (direct) {
                    if (lower.contains("magisk") || lower.contains("zygisk")) {
                        hits.add(trim(line));
                    }
                } else if (isSuspiciousMountConsistency(lower)) {
                    hits.add(trim(line));
                }
            }
        } catch (Throwable ignored) {
            return hits;
        } finally {
            try { if (br != null) br.close(); } catch (Throwable ignored) {}
        }
        return hits;
    }

    private boolean isSuspiciousMountConsistency(String lowerLine) {
        if (lowerLine == null || lowerLine.isEmpty()) return false;
        if (isKnownOemOverlay(lowerLine)) return false;
        if (!isExactSensitiveTarget(lowerLine)) return false;

        return lowerLine.contains("magisk")
                || lowerLine.contains("zygisk")
                || lowerLine.contains(" - overlay ")
                || lowerLine.contains(" - tmpfs ")
                || lowerLine.contains("upperdir=")
                || lowerLine.contains("workdir=")
                || lowerLine.contains("redirect_dir=")
                || lowerLine.contains("metacopy=")
                || lowerLine.contains("/dev/root");
    }

    private List<String> readBootConsistencyHits() {
        List<String> hits = new ArrayList<>();
        String verifiedBoot = lower(SystemProp.firstNonEmpty(
                SystemProp.get("ro.boot.verifiedbootstate"),
                SystemProp.get("ro.boot.vbmeta.device_state")
        ));
        String flashLocked = lower(SystemProp.firstNonEmpty(
                SystemProp.get("ro.boot.flash.locked"),
                SystemProp.get("ro.boot.bootloader.locked"),
                SystemProp.get("ro.boot.locked")
        ));
        String verity = lower(SystemProp.get("ro.boot.veritymode"));
        String secure = lower(SystemProp.get("ro.secure"));
        String debuggable = lower(SystemProp.get("ro.debuggable"));

        if ("green".equals(verifiedBoot) && "1".equals(flashLocked) &&
                ("disabled".equals(verity) || "logging".equals(verity))) {
            hits.add("green+locked but verity=" + verity);
        }
        if ("green".equals(verifiedBoot) && "1".equals(flashLocked) &&
                ("0".equals(secure) || "1".equals(debuggable))) {
            hits.add("green+locked but ro.secure=" + secure + " ro.debuggable=" + debuggable);
        }
        return hits;
    }

    private List<String> readStringConsistencyHits() {
        List<String> out = new ArrayList<>();
        addIfTrace(out, "Build.TAGS", android.os.Build.TAGS);
        addIfTrace(out, "os.version", System.getProperty("os.version"));
        addIfTrace(out, "proc.version", readFirstLine(new File("/proc/version")));
        return out;
    }

    private void addIfTrace(List<String> out, String label, String value) {
        if (value == null || value.trim().isEmpty()) return;
        String lower = value.toLowerCase(Locale.US);
        if (lower.contains("magisk") || lower.contains("zygisk") || lower.contains("shamiko")) {
            out.add(label + "=" + value.trim());
        }
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

    private boolean isExactSensitiveTarget(String lowerLine) {
        return lowerLine.contains(" / /system ")
                || lowerLine.contains(" / /vendor ")
                || lowerLine.contains(" / /product ")
                || lowerLine.contains(" / /system_ext ")
                || lowerLine.contains(" / /odm ");
    }

    private boolean isKnownOemOverlay(String lowerLine) {
        return lowerLine.contains("oplus_overlay")
                || lowerLine.contains("overlay-overlay")
                || lowerLine.contains("/mnt/opex/")
                || lowerLine.contains(" /apex/")
                || lowerLine.contains(" /bootstrap-apex/")
                || lowerLine.contains("/my_product/")
                || lowerLine.contains("/my_region/")
                || lowerLine.contains("/my_preload/")
                || lowerLine.contains("/my_heytap/")
                || lowerLine.contains("/my_stock/");
    }

    private String trim(String line) {
        if (line == null) return "";
        String t = line.trim();
        return t.length() <= 180 ? t : t.substring(0, 180) + "...";
    }

    private String lower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.US);
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
