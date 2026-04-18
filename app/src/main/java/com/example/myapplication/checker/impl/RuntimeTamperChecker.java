package com.example.myapplication.checker.impl;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.InstallSourceInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Debug;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;
import com.example.myapplication.checker.util.LocalPort;
import com.example.myapplication.checker.util.ProcScan;
import com.example.myapplication.checker.util.SystemProp;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class RuntimeTamperChecker implements IChecker {

    @Override public String id() { return "runtime_tamper"; }

    @Override public String title() { return "Инъекции и хуки"; }

    @Override
    public CheckerResult run(Context context) {
        List<String> hits = new ArrayList<>();
        List<String> details = new ArrayList<>();

        // 1) Debugger
        boolean dbg = isDebuggerAttached();
        boolean dbgRepeat = isDebuggerAttached();
        details.add("debugger=" + dbg);
        details.add("debugger_repeat=" + dbgRepeat);
        if (dbg || dbgRepeat) hits.add("debugger");
        if (dbg != dbgRepeat) hits.add("debugger-flap");

        // 1.1) TracerPid (ptrace/debugger)
        int tracerPid = readTracerPid();
        int tracerPidRepeat = readTracerPid();
        details.add("tracerPid=" + tracerPid);
        details.add("tracerPid_repeat=" + tracerPidRepeat);
        if (tracerPid > 0 || tracerPidRepeat > 0) hits.add("tracerpid");
        if (tracerPid != tracerPidRepeat) hits.add("tracerpid-flap");

        // 2) Frida gadget / gum / substrings в memory maps (best-effort)
        boolean fridaInMaps = ProcScan.selfMapsContains(
                "frida", "gum-js-loop", "libfrida", "gadget", "frida-gadget", "libfrida-gadget"
        );
        boolean fridaInMapsRepeat = ProcScan.selfMapsContains(
                "frida", "gum-js-loop", "libfrida", "gadget", "frida-gadget", "libfrida-gadget"
        );
        details.add("maps(frida/gum/gadget)=" + fridaInMaps);
        details.add("maps_repeat(frida/gum/gadget)=" + fridaInMapsRepeat);
        if (fridaInMaps || fridaInMapsRepeat) hits.add("frida-maps");
        if (fridaInMaps != fridaInMapsRepeat) hits.add("frida-maps-flap");

        // 2.1) Xposed/LSPosed/Riru/Zygisk сигнатуры в maps (best-effort)
        boolean hookInMaps = ProcScan.selfMapsContains(
                "xposed", "lsposed", "edxp", "riru", "zygisk", "magisk", "substrate",
                "substrate-loader", "libsubstrate", "frida-agent"
        );
        boolean hookInMapsRepeat = ProcScan.selfMapsContains(
                "xposed", "lsposed", "edxp", "riru", "zygisk", "magisk", "substrate",
                "substrate-loader", "libsubstrate", "frida-agent"
        );
        details.add("maps(hooks/zygisk/riru)=" + hookInMaps);
        details.add("maps_repeat(hooks/zygisk/riru)=" + hookInMapsRepeat);
        if (hookInMaps || hookInMapsRepeat) hits.add("hook-maps");
        if (hookInMaps != hookInMapsRepeat) hits.add("hook-maps-flap");

        // 3) Frida-server порты (часто 27042/27043) — best-effort
        boolean fridaPort = LocalPort.isOpen(27042, 120) || LocalPort.isOpen(27043, 120);
        boolean fridaPortRepeat = LocalPort.isOpen(27042, 120) || LocalPort.isOpen(27043, 120);
        details.add("port(27042/27043)=" + fridaPort);
        details.add("port_repeat(27042/27043)=" + fridaPortRepeat);
        if (fridaPort || fridaPortRepeat) hits.add("frida-port");
        if (fridaPort != fridaPortRepeat) hits.add("frida-port-flap");

        // 4) Xposed/LSPosed классы — best-effort
        boolean hookClasses = classExists("de.robv.android.xposed.XposedBridge")
                || classExists("de.robv.android.xposed.XC_MethodHook")
                || classExists("org.lsposed.lspd.core.Main")
                || classExists("io.github.lsposed.lspd.core.Main");
        details.add("classes(xposed/lsposed)=" + hookClasses);
        if (hookClasses) hits.add("hook-classes");

        // 5) suspicious unix sockets (best-effort)
        boolean sockHit = ProcScan.fileContains("/proc/net/unix",
                "frida", "gum", "xposed", "lsposed", "zygisk", "magisk", "magiskd", "substrate");
        boolean sockHitRepeat = ProcScan.fileContains("/proc/net/unix",
                "frida", "gum", "xposed", "lsposed", "zygisk", "magisk", "magiskd", "substrate");
        details.add("unix_sockets(suspicious)=" + sockHit);
        details.add("unix_sockets_repeat(suspicious)=" + sockHitRepeat);
        if (sockHit || sockHitRepeat) hits.add("socket-suspicious");
        if (sockHit != sockHitRepeat) hits.add("socket-flap");

        // 5.1) magisk-related system properties (best-effort)
        List<String> magiskProps = readMagiskProps();
        if (!magiskProps.isEmpty()) {
            details.add("magisk_props=" + join(magiskProps, ", "));
            hits.add("magisk-prop");
        } else {
            details.add("magisk_props=none");
        }

        // 6) suspicious process cmdlines (best-effort)
        boolean procHit = scanProcCmdlines(
                "frida", "gadget", "xposed", "lsposed", "zygisk", "magisk", "magiskd",
                "substrate", "riru", "edxp"
        );
        boolean procHitRepeat = scanProcCmdlines(
                "frida", "gadget", "xposed", "lsposed", "zygisk", "magisk", "magiskd",
                "substrate", "riru", "edxp"
        );
        details.add("proc_cmdline(suspicious)=" + procHit);
        details.add("proc_cmdline_repeat(suspicious)=" + procHitRepeat);
        if (procHit || procHitRepeat) hits.add("proc-suspicious");
        if (procHit != procHitRepeat) hits.add("proc-flap");

        // 6.1) suspicious TCP ports in /proc/net/tcp (best-effort)
        boolean tcpHit = scanTcpPorts(27042, 27043, 23946, 23947);
        boolean tcpHitRepeat = scanTcpPorts(27042, 27043, 23946, 23947);
        details.add("tcp_ports(suspicious)=" + tcpHit);
        details.add("tcp_ports_repeat(suspicious)=" + tcpHitRepeat);
        if (tcpHit || tcpHitRepeat) hits.add("tcp-ports");
        if (tcpHit != tcpHitRepeat) hits.add("tcp-flap");

        // 5) Zygisk/Riru props (best-effort)
        boolean zygiskProp = ProcScan.fileContains("/proc/self/mounts", "zygisk");
        details.add("mounts(zygisk)=" + zygiskProp);
        if (zygiskProp) hits.add("zygisk-mount");

        // 7) libc hooks via LD_PRELOAD (rare on Android but signal)
        String ldPreload = readEnv("LD_PRELOAD");
        details.add("env(LD_PRELOAD)=" + (ldPreload.isEmpty() ? "empty" : ldPreload));
        if (!ldPreload.isEmpty()) hits.add("ld-preload");

        // 8) suspicious libraries loaded in /proc/self/maps (extra)
        boolean extraLibs = ProcScan.selfMapsContains(
                "libhook", "libxposed", "libsubstrate", "libfrida", "libedxp", "liblsposed"
        );
        details.add("maps(extra-libs)=" + extraLibs);
        if (extraLibs) hits.add("extra-libs");

        List<String> stackHits = readSuspiciousStackTraces();
        details.add("stack_trace_hits=" + (stackHits.isEmpty() ? "none" : join(stackHits, ", ")));
        if (!stackHits.isEmpty()) hits.add("stack-trace");

        SelfIntegrity integrity = inspectSelfIntegrity(context);
        details.add("self_integrity=" + integrity.summary);
        if (integrity.suspicious) hits.add("self-integrity");

        List<String> classLoaderHits = readClassLoaderHits(context);
        details.add("classloader_hits=" + (classLoaderHits.isEmpty() ? "none" : join(classLoaderHits, ", ")));
        if (!classLoaderHits.isEmpty()) hits.add("classloader");

        if (!hits.isEmpty()) {
            boolean strong = dbg || dbgRepeat
                    || tracerPid > 0 || tracerPidRepeat > 0
                    || fridaInMaps || fridaInMapsRepeat
                    || fridaPort || fridaPortRepeat
                    || integrity.highRisk
                    || !classLoaderHits.isEmpty();
            boolean fail = strong && hits.size() >= 2;
            String title = fail ? "Обнаружено вмешательство" : "Подозрительные сигналы";
            StringBuilder body = new StringBuilder();
            body.append("Обнаружены признаки вмешательства: ");
            body.append(join(hits, ", "));
            body.append(".\n\nСигналы:\n");
            for (String d : details) {
                body.append("• ").append(d).append("\n");
            }
            return fail
                    ? CheckerResult.fail(title, body.toString().trim())
                    : CheckerResult.warn(title, body.toString().trim());
        }

        return CheckerResult.pass(
                "Вмешательств не выявлено",
                "Явных признаков дебаггера/хуков не найдено.\n\nСигналы:\n• "
                        + join(details, "\n• ")
        );
    }

    private boolean isDebuggerAttached() {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger();
    }

    private boolean classExists(String name) {
        try {
            Class.forName(name);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    private int readTracerPid() {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/self/status"));
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    String v = line.substring("TracerPid:".length()).trim();
                    return Integer.parseInt(v);
                }
            }
        } catch (Throwable ignored) {
        } finally {
            try { if (br != null) br.close(); } catch (Throwable ignored) {}
        }
        return 0;
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

    private List<String> readSuspiciousStackTraces() {
        List<String> hits = new ArrayList<>();
        try {
            StackTraceElement[] stack = Thread.currentThread().getStackTrace();
            for (StackTraceElement el : stack) {
                if (el == null) continue;
                String line = (el.getClassName() + "." + el.getMethodName()).toLowerCase(Locale.US);
                if (line.contains("xposed")
                        || line.contains("lsposed")
                        || line.contains("edxp")
                        || line.contains("frida")) {
                    hits.add(el.getClassName());
                }
            }
        } catch (Throwable ignored) {
        }
        return hits;
    }

    private SelfIntegrity inspectSelfIntegrity(Context context) {
        List<String> findings = new ArrayList<>();
        boolean suspicious = false;
        boolean highRisk = false;

        if (context == null) {
            return new SelfIntegrity("no-context", false, false);
        }

        try {
            ApplicationInfo ai = context.getApplicationInfo();
            String packageCodePath = context.getPackageCodePath();
            String sourceDir = ai == null ? "" : safe(ai.sourceDir);
            findings.add("packageCodePath=" + safe(packageCodePath));
            findings.add("sourceDir=" + sourceDir);
            if (!safe(packageCodePath).equals(sourceDir)) {
                suspicious = true;
                findings.add("codePathMismatch=true");
            }
            if (sourceDir.contains("/data/local/tmp") || sourceDir.contains("/storage/")) {
                suspicious = true;
                highRisk = true;
                findings.add("unexpectedInstallPath=true");
            }
            if (sourceDir.contains("/virtual/")
                    || sourceDir.contains("/parallel/")
                    || sourceDir.contains("/container/")) {
                suspicious = true;
                highRisk = true;
                findings.add("virtualizedInstallPath=true");
            }
            if (ai != null && ai.splitSourceDirs != null && ai.splitSourceDirs.length > 0) {
                findings.add("splitCount=" + ai.splitSourceDirs.length);
                for (String split : ai.splitSourceDirs) {
                    String safeSplit = safe(split);
                    if (safeSplit.contains("/data/local/tmp")
                            || safeSplit.contains("/storage/")
                            || safeSplit.contains("/virtual/")
                            || safeSplit.contains("/parallel/")) {
                        suspicious = true;
                        findings.add("suspiciousSplit=" + safeSplit);
                    }
                }
            }
            String nativeLibDir = ai == null ? "" : safe(ai.nativeLibraryDir);
            findings.add("nativeLibraryDir=" + nativeLibDir);
            if (nativeLibDir.contains("/data/local/tmp")
                    || nativeLibDir.contains("/storage/")
                    || nativeLibDir.contains("/virtual/")
                    || nativeLibDir.contains("/parallel/")) {
                suspicious = true;
                highRisk = true;
                findings.add("unexpectedNativeLibDir=true");
            }
        } catch (Throwable t) {
            findings.add("pathError=" + t.getClass().getSimpleName());
        }

        String installer = readInstaller(context);
        findings.add("installer=" + installer);
        if (installer.isEmpty() || "adb".equals(installer) || "unknown".equals(installer)) {
            suspicious = true;
            findings.add("installerSuspicious=true");
        }
        if (installer.contains("vmos")
                || installer.contains("virtual")
                || installer.contains("parallel")
                || installer.contains("dual")
                || installer.contains("clone")) {
            suspicious = true;
            highRisk = true;
            findings.add("installerVirtualized=true");
        }

        SignatureInfo sig = readSignatureInfo(context);
        findings.add(sig.summary);
        if (sig.suspicious) {
            suspicious = true;
        }
        if (sig.highRisk) {
            highRisk = true;
        }

        return new SelfIntegrity(join(findings, "; "), suspicious, highRisk);
    }

    private List<String> readClassLoaderHits(Context context) {
        List<String> hits = new ArrayList<>();
        try {
            ClassLoader self = RuntimeTamperChecker.class.getClassLoader();
            String selfLoader = self == null ? "null" : self.getClass().getName();
            if (isSuspiciousClassLoader(selfLoader)) {
                hits.add("self=" + selfLoader);
            }
        } catch (Throwable ignored) {
        }

        if (context == null) {
            return hits;
        }

        try {
            ClassLoader app = context.getClassLoader();
            String appLoader = app == null ? "null" : app.getClass().getName();
            if (isSuspiciousClassLoader(appLoader)) {
                hits.add("app=" + appLoader);
            }
        } catch (Throwable ignored) {
        }

        try {
            ClassLoader system = ClassLoader.getSystemClassLoader();
            String sysLoader = system == null ? "null" : system.getClass().getName();
            if (isSuspiciousClassLoader(sysLoader)) {
                hits.add("system=" + sysLoader);
            }
        } catch (Throwable ignored) {
        }
        return hits;
    }

    private boolean isSuspiciousClassLoader(String className) {
        if (className == null || className.trim().isEmpty()) {
            return false;
        }
        String lower = className.toLowerCase(Locale.US);
        return lower.contains("xposed")
                || lower.contains("lsposed")
                || lower.contains("edxp")
                || lower.contains("frida")
                || lower.contains("sandhook")
                || lower.contains("epic")
                || lower.contains("substrate")
                || lower.contains("vmos")
                || lower.contains("parallel")
                || lower.contains("virtual");
    }

    private String readInstaller(Context context) {
        if (context == null) return "unknown";
        try {
            PackageManager pm = context.getPackageManager();
            String pkg = context.getPackageName();
            if (pm == null || pkg == null) return "unknown";
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                InstallSourceInfo info = pm.getInstallSourceInfo(pkg);
                String installer = info == null ? "" : safe(info.getInstallingPackageName());
                return installer.isEmpty() ? "adb" : installer;
            }
            String installer = pm.getInstallerPackageName(pkg);
            return installer == null || installer.trim().isEmpty() ? "adb" : installer.trim();
        } catch (Throwable ignored) {
            return "unknown";
        }
    }

    private SignatureInfo readSignatureInfo(Context context) {
        if (context == null) return new SignatureInfo("signatures=unknown", false, false);
        try {
            PackageManager pm = context.getPackageManager();
            if (pm == null) return new SignatureInfo("signatures=pm-null", false, false);

            PackageInfo pi;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pi = pm.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
                if (pi.signingInfo == null) {
                    return new SignatureInfo("signatures=none", true, false);
                }
                Signature[] signers = pi.signingInfo.getApkContentsSigners();
                return summarizeSignatures(signers);
            }
            pi = pm.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
            return summarizeSignatures(pi.signatures);
        } catch (Throwable t) {
            return new SignatureInfo("signaturesError=" + t.getClass().getSimpleName(), false, false);
        }
    }

    private SignatureInfo summarizeSignatures(Signature[] signatures) {
        if (signatures == null || signatures.length == 0) {
            return new SignatureInfo("signatures=none", true, false);
        }
        List<String> digests = new ArrayList<>();
        boolean suspicious = signatures.length > 1;
        boolean highRisk = false;
        for (Signature s : signatures) {
            String sha = sha256(s == null ? null : s.toByteArray());
            if (!sha.isEmpty()) digests.add(sha);
        }
        String joined = digests.isEmpty() ? "none" : join(digests, ",");
        if (joined.contains("NONE")) suspicious = true;
        return new SignatureInfo("signatureCount=" + signatures.length + "; signatureSha256=" + joined, suspicious, highRisk);
    }

    private String sha256(byte[] data) {
        if (data == null || data.length == 0) return "";
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(data);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < digest.length; i++) {
                if (i > 0) sb.append(':');
                sb.append(String.format(Locale.US, "%02X", digest[i]));
            }
            return sb.toString();
        } catch (Throwable ignored) {
            return "";
        }
    }

    private String safe(String value) {
        return value == null ? "" : value.trim();
    }

    private static final class SelfIntegrity {
        final String summary;
        final boolean suspicious;
        final boolean highRisk;

        SelfIntegrity(String summary, boolean suspicious, boolean highRisk) {
            this.summary = summary == null ? "" : summary;
            this.suspicious = suspicious;
            this.highRisk = highRisk;
        }
    }

    private static final class SignatureInfo {
        final String summary;
        final boolean suspicious;
        final boolean highRisk;

        SignatureInfo(String summary, boolean suspicious, boolean highRisk) {
            this.summary = summary == null ? "" : summary;
            this.suspicious = suspicious;
            this.highRisk = highRisk;
        }
    }

    private boolean scanProcCmdlines(String... needles) {
        File proc = new File("/proc");
        File[] entries = proc.listFiles();
        if (entries == null) return false;

        int scanned = 0;
        for (File f : entries) {
            if (scanned > 200) break; // лимит для производительности
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

    private boolean scanTcpPorts(int... ports) {
        return fileHasTcpPort("/proc/net/tcp", ports) || fileHasTcpPort("/proc/net/tcp6", ports);
    }

    private boolean fileHasTcpPort(String path, int... ports) {
        File f = new File(path);
        if (!f.canRead()) return false;
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(f));
            String line;
            boolean header = true;
            while ((line = br.readLine()) != null) {
                if (header) { header = false; continue; }
                String[] parts = line.trim().split("\\s+");
                if (parts.length < 2) continue;
                String local = parts[1]; // hex addr:port
                int idx = local.indexOf(':');
                if (idx < 0 || idx + 1 >= local.length()) continue;
                String portHex = local.substring(idx + 1);
                int port = parseHexPort(portHex);
                if (port <= 0) continue;
                for (int p : ports) {
                    if (p == port) return true;
                }
            }
        } catch (Throwable ignored) {
            return false;
        } finally {
            try { if (br != null) br.close(); } catch (Throwable ignored) {}
        }
        return false;
    }

    private int parseHexPort(String hex) {
        if (hex == null || hex.isEmpty()) return -1;
        try {
            return Integer.parseInt(hex, 16);
        } catch (Throwable ignored) {
            return -1;
        }
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

    private String readEnv(String key) {
        if (key == null) return "";
        try {
            String v = System.getenv(key);
            return v == null ? "" : v.trim();
        } catch (Throwable ignored) {
            return "";
        }
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
