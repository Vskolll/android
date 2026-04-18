package com.example.myapplication.checker.impl;

import android.content.Context;
import android.os.Build;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;
import com.example.myapplication.checker.util.PackageCheck;
import com.example.myapplication.checker.util.ProcScan;
import com.example.myapplication.checker.util.SystemProp;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

public class KernelChecker implements IChecker {

    private static final Pattern TOKEN_KERNELSU = Pattern.compile("(^|[^a-z0-9_])kernelsu([^a-z0-9_]|$)");
    private static final Pattern TOKEN_KSUD = Pattern.compile("(^|[^a-z0-9_])ksud([^a-z0-9_]|$)");
    private static final Pattern TOKEN_SUSFS = Pattern.compile("(^|[^a-z0-9_])susfs([^a-z0-9_]|$)");
    private static final Pattern TOKEN_SUS_FS = Pattern.compile("(^|[^a-z0-9_])sus_fs([^a-z0-9_]|$)");
    private static final Pattern TOKEN_KSU_NEXT = Pattern.compile("(^|[^a-z0-9_])ksu-next([^a-z0-9_]|$)");
    private static final Pattern TOKEN_SUKISU = Pattern.compile("(^|[^a-z0-9_])sukisu([^a-z0-9_]|$)");

    @Override
    public String id() {
        return "kernel";
    }

    @Override
    public String title() {
        return "KErnel";
    }

    @Override
    public CheckerResult run(Context context) {
        List<String> directHits = new ArrayList<>();
        List<String> indirectHits = new ArrayList<>();
        List<String> details = new ArrayList<>();

        boolean kernelSuPkg = PackageCheck.isInstalled(context, "me.weishu.kernelsu")
                || PackageCheck.isInstalled(context, "me.weishu.kernelsu.debug")
                || PackageCheck.isInstalled(context, "me.weishu.kernelsu.nightly");
        boolean kernelSuToolsPkg = PackageCheck.isInstalled(context, "com.rifsxd.ksunext");
        details.add("pkg_kernelsu=" + kernelSuPkg);
        details.add("pkg_ksunext=" + kernelSuToolsPkg);
        if (kernelSuPkg || kernelSuToolsPkg) {
            directHits.add("package");
        }

        String fileHit = firstExisting(
                "/proc/ksu",
                "/proc/susfs",
                "/sys/module/kernelsu",
                "/sys/module/susfs",
                "/sys/fs/selinux/features/kernelsu",
                "/sys/fs/selinux/features/susfs",
                "/sys/kernel/ksu",
                "/sys/kernel/ksu/version",
                "/sys/kernel/susfs",
                "/data/adb/ksu",
                "/data/adb/ksud",
                "/data/adb/ksu/bin/ksud",
                "/data/adb/modules/ksu",
                "/data/adb/modules/kernelsu",
                "/data/adb/modules/susfs",
                "/debug_ramdisk/ksuinit",
                "/dev/ksu"
        );
        details.add("file_hit=" + (fileHit == null ? "none" : fileHit));
        if (fileHit != null) {
            directHits.add("file");
        }

        boolean mountsHit = ProcScan.fileContains(
                "/proc/self/mounts",
                "kernelsu", "ksud", "susfs", "sus_fs"
        );
        details.add("mounts(kernelsu/susfs)=" + mountsHit);
        if (mountsHit) {
            directHits.add("mounts");
        }

        boolean mapsHit = ProcScan.selfMapsContains(
                "kernelsu", "ksud", "susfs"
        );
        details.add("maps(kernelsu/ksud/susfs)=" + mapsHit);
        if (mapsHit) {
            directHits.add("maps");
        }

        boolean socketHit = ProcScan.fileContains(
                "/proc/net/unix",
                "kernelsu", "ksud", "susfs"
        );
        details.add("unix_sockets(kernelsu/ksud/susfs)=" + socketHit);
        if (socketHit) {
            directHits.add("socket");
        }

        List<String> mountInfoHits = readMountInfoHits();
        details.add("mountinfo_hits=" + (mountInfoHits.isEmpty() ? "none" : join(mountInfoHits, " | ")));
        if (!mountInfoHits.isEmpty()) {
            directHits.add("mountinfo");
        }

        List<String> mountConsistencyHits = readMountConsistencyHits();
        details.add("mount_consistency=" + (mountConsistencyHits.isEmpty() ? "none" : join(mountConsistencyHits, " | ")));
        if (!mountConsistencyHits.isEmpty()) {
            indirectHits.add("mount-consistency");
        }

        boolean modulesHit = ProcScan.fileContains(
                "/proc/modules",
                "kernelsu", "ksud", "susfs", "sus_fs"
        );
        details.add("proc_modules(kernelsu/susfs)=" + modulesHit);
        if (modulesHit) {
            directHits.add("module");
        }

        boolean fsHit = ProcScan.fileContains(
                "/proc/filesystems",
                "susfs", "sus_fs"
        );
        details.add("filesystems(susfs)=" + fsHit);
        if (fsHit) {
            directHits.add("filesystem");
        }

        String statusLine = firstNonEmptyLine(
                "/proc/ksu",
                "/sys/kernel/ksu/version",
                "/sys/kernel/ksu/ksud",
                "/proc/susfs"
        );
        details.add("status_line=" + (statusLine.isEmpty() ? "none" : statusLine));
        if (!statusLine.isEmpty() && containsKernelKeywords(statusLine)) {
            directHits.add("status");
        }

        List<String> propHits = readKernelProps();
        if (!propHits.isEmpty()) {
            details.add("props=" + join(propHits, ", "));
            directHits.add("prop");
        } else {
            details.add("props=none");
        }

        List<String> kernelStringHits = readKernelStringHits();
        details.add("kernel_strings=" + (kernelStringHits.isEmpty() ? "none" : join(kernelStringHits, ", ")));
        if (!kernelStringHits.isEmpty()) {
            indirectHits.add("kernel-string");
        }

        int indirectScore = indirectHits.size();
        boolean directDetected = !directHits.isEmpty();
        boolean strongIndirect = indirectScore >= 2;
        boolean weakIndirect = indirectScore == 1;

        details.add("direct_hits=" + (directHits.isEmpty() ? "none" : join(directHits, ", ")));
        details.add("indirect_hits=" + (indirectHits.isEmpty() ? "none" : join(indirectHits, ", ")));
        details.add("indirect_score=" + indirectScore);

        if (directDetected || strongIndirect || weakIndirect) {
            StringBuilder body = new StringBuilder();
            body.append("Обнаружены признаки kernel-level tamper: ");
            body.append(join(combineHits(directHits, indirectHits), ", "));
            body.append(".\n\nСигналы:\n• ");
            body.append(join(details, "\n• "));
            if (directDetected || strongIndirect) {
                return CheckerResult.fail("KernelSU/SusFS обнаружен", body.toString());
            }
            return CheckerResult.warn("Косвенные kernel-признаки", body.toString());
        }

        return CheckerResult.pass(
                "KernelSU/SusFS не обнаружен",
                "Явных признаков KernelSU/SusFS не найдено.\n\nСигналы:\n• " + join(details, "\n• ")
        );
    }

    private List<String> combineHits(List<String> a, List<String> b) {
        List<String> out = new ArrayList<>();
        if (a != null) {
            out.addAll(a);
        }
        if (b != null) {
            out.addAll(b);
        }
        return out;
    }

    private String firstExisting(String... paths) {
        for (String p : paths) {
            try {
                if (new File(p).exists()) {
                    return p;
                }
            } catch (Throwable ignored) {
            }
        }
        return null;
    }

    private List<String> readMountInfoHits() {
        List<String> hits = new ArrayList<>();
        File f = new File("/proc/self/mountinfo");
        if (!f.canRead()) {
            return hits;
        }

        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(f));
            String line;
            while ((line = br.readLine()) != null) {
                String lower = line.toLowerCase(Locale.US);

                if (containsKernelKeywords(lower)) {
                    hits.add(trimMountInfo(line));
                    continue;
                }

                if (isSuspiciousSystemOverlay(lower)) {
                    hits.add(trimMountInfo(line));
                }
            }
        } catch (Throwable ignored) {
            return hits;
        } finally {
            try {
                if (br != null) {
                    br.close();
                }
            } catch (Throwable ignored) {
            }
        }
        return hits;
    }

    private List<String> readMountConsistencyHits() {
        List<String> hits = new ArrayList<>();
        File f = new File("/proc/self/mountinfo");
        if (!f.canRead()) {
            return hits;
        }

        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(f));
            String line;
            while ((line = br.readLine()) != null) {
                MountInfo info = parseMountInfo(line);
                if (info == null || !isSensitiveTarget(info.mountPoint)) {
                    continue;
                }

                if (isUnexpectedSystemFs(info)) {
                    hits.add(info.mountPoint + " fs=" + info.fsType + " src=" + shorten(info.source));
                    continue;
                }

                if (hasOverlayLikeOptions(info)) {
                    hits.add(info.mountPoint + " opts=" + shorten(info.superOptions));
                    continue;
                }

                if (hasSuspiciousSource(info)) {
                    hits.add(info.mountPoint + " src=" + shorten(info.source));
                }
            }
        } catch (Throwable ignored) {
            return hits;
        } finally {
            try {
                if (br != null) {
                    br.close();
                }
            } catch (Throwable ignored) {
            }
        }
        return hits;
    }

    private String firstNonEmptyLine(String... paths) {
        for (String p : paths) {
            String line = readFirstLine(p);
            if (!line.isEmpty()) {
                return line;
            }
        }
        return "";
    }

    private String readFirstLine(String path) {
        File f = new File(path);
        if (!f.canRead()) {
            return "";
        }
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(f));
            String line = br.readLine();
            return line == null ? "" : line.trim();
        } catch (Throwable ignored) {
            return "";
        } finally {
            try {
                if (br != null) {
                    br.close();
                }
            } catch (Throwable ignored) {
            }
        }
    }

    private List<String> readKernelProps() {
        String[] keys = new String[] {
                "ro.kernel.su",
                "ro.ksu.version",
                "ro.ksu.variant",
                "persist.ksu.enabled",
                "persist.sys.ksu",
                "persist.sys.susfs",
                "ro.susfs.version",
                "ro.susfs.enabled"
        };
        List<String> out = new ArrayList<>();
        for (String key : keys) {
            String value = SystemProp.get(key);
            if (!value.isEmpty()) {
                out.add(key + "=" + value);
            }
        }
        return out;
    }

    private List<String> readKernelStringHits() {
        List<String> out = new ArrayList<>();
        addIfKernelTrace(out, "Build.DISPLAY", Build.DISPLAY);
        addIfKernelTrace(out, "Build.FINGERPRINT", Build.FINGERPRINT);
        addIfKernelTrace(out, "Build.HOST", Build.HOST);
        addIfKernelTrace(out, "Build.TAGS", Build.TAGS);
        addIfKernelTrace(out, "os.version", System.getProperty("os.version"));
        addIfKernelTrace(out, "uname.version", readFirstLine("/proc/version"));
        return out;
    }

    private void addIfKernelTrace(List<String> out, String label, String value) {
        if (value == null || value.trim().isEmpty()) {
            return;
        }
        String lower = value.toLowerCase(Locale.US);
        if (containsKernelKeyword(lower)) {
            out.add(label + "=" + value.trim());
        }
    }

    private boolean containsKernelKeywords(String value) {
        String lower = value == null ? "" : value.toLowerCase(Locale.US);
        return containsKernelKeyword(lower);
    }

    private boolean containsKernelKeyword(String lower) {
        if (lower == null || lower.isEmpty()) {
            return false;
        }
        return TOKEN_KERNELSU.matcher(lower).find()
                || TOKEN_KSUD.matcher(lower).find()
                || TOKEN_SUSFS.matcher(lower).find()
                || TOKEN_SUS_FS.matcher(lower).find()
                || TOKEN_KSU_NEXT.matcher(lower).find()
                || TOKEN_SUKISU.matcher(lower).find();
    }

    private boolean isSensitiveTarget(String mountPoint) {
        if (mountPoint == null) {
            return false;
        }
        return "/system".equals(mountPoint)
                || "/vendor".equals(mountPoint)
                || "/product".equals(mountPoint)
                || "/system_ext".equals(mountPoint)
                || "/odm".equals(mountPoint);
    }

    private boolean isUnexpectedSystemFs(MountInfo info) {
        String fs = lower(info.fsType);
        if (fs.isEmpty()) {
            return false;
        }
        if (fs.contains("overlay") || fs.contains("tmpfs") || fs.contains("fuse")) {
            return true;
        }
        return false;
    }

    private boolean hasOverlayLikeOptions(MountInfo info) {
        String opts = lower(info.superOptions) + " " + lower(info.mountOptions);
        return opts.contains("upperdir=")
                || opts.contains("workdir=")
                || opts.contains("redirect_dir=")
                || opts.contains("metacopy=");
    }

    private boolean hasSuspiciousSource(MountInfo info) {
        String src = lower(info.source);
        if (src.isEmpty()) {
            return false;
        }
        return src.contains("tmpfs")
                || src.contains("overlay")
                || src.contains("magisk")
                || src.contains("kernelsu")
                || src.contains("susfs")
                || src.contains("/dev/block/loop")
                || src.contains("/dev/root");
    }

    private boolean isSuspiciousSystemOverlay(String lowerLine) {
        boolean sensitiveTarget = lowerLine.contains(" /system ")
                || lowerLine.contains(" /vendor ")
                || lowerLine.contains(" /product ")
                || lowerLine.contains(" /system_ext ")
                || lowerLine.contains(" /odm ");
        if (!sensitiveTarget) {
            return false;
        }
        return lowerLine.contains(" - overlay ")
                || lowerLine.contains(" - tmpfs ")
                || lowerLine.contains("upperdir=")
                || lowerLine.contains("workdir=");
    }

    private String trimMountInfo(String line) {
        if (line == null) {
            return "";
        }
        String t = line.trim();
        if (t.length() <= 180) {
            return t;
        }
        return t.substring(0, 180) + "...";
    }

    private String shorten(String value) {
        if (value == null) {
            return "";
        }
        String t = value.trim();
        if (t.length() <= 72) {
            return t;
        }
        return t.substring(0, 72) + "...";
    }

    private String lower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.US);
    }

    private MountInfo parseMountInfo(String line) {
        if (line == null) {
            return null;
        }
        String[] halves = line.split(" - ", 2);
        if (halves.length != 2) {
            return null;
        }

        String[] left = halves[0].trim().split("\\s+");
        String[] right = halves[1].trim().split("\\s+");
        if (left.length < 6 || right.length < 3) {
            return null;
        }

        String mountPoint = left[4];
        String mountOptions = left[5];
        String fsType = right[0];
        String source = right[1];
        String superOptions = right[2];
        return new MountInfo(mountPoint, mountOptions, fsType, source, superOptions);
    }

    private static final class MountInfo {
        final String mountPoint;
        final String mountOptions;
        final String fsType;
        final String source;
        final String superOptions;

        MountInfo(String mountPoint, String mountOptions, String fsType, String source, String superOptions) {
            this.mountPoint = mountPoint == null ? "" : mountPoint;
            this.mountOptions = mountOptions == null ? "" : mountOptions;
            this.fsType = fsType == null ? "" : fsType;
            this.source = source == null ? "" : source;
            this.superOptions = superOptions == null ? "" : superOptions;
        }
    }

    private static String join(List<String> xs, String sep) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < xs.size(); i++) {
            if (i > 0) {
                sb.append(sep);
            }
            sb.append(xs.get(i));
        }
        return sb.toString();
    }
}
