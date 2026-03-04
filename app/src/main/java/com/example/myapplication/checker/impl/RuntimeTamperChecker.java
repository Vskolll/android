package com.example.myapplication.checker.impl;

import android.content.Context;
import android.os.Debug;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;
import com.example.myapplication.checker.util.LocalPort;
import com.example.myapplication.checker.util.ProcScan;
import com.example.myapplication.checker.util.SystemProp;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
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
        boolean dbg = Debug.isDebuggerConnected() || Debug.waitingForDebugger();
        details.add("debugger=" + dbg);
        if (dbg) hits.add("debugger");

        // 1.1) TracerPid (ptrace/debugger)
        int tracerPid = readTracerPid();
        details.add("tracerPid=" + tracerPid);
        if (tracerPid > 0) hits.add("tracerpid");

        // 2) Frida gadget / gum / substrings в memory maps (best-effort)
        boolean fridaInMaps = ProcScan.selfMapsContains(
                "frida", "gum-js-loop", "libfrida", "gadget", "frida-gadget", "libfrida-gadget"
        );
        details.add("maps(frida/gum/gadget)=" + fridaInMaps);
        if (fridaInMaps) hits.add("frida-maps");

        // 2.1) Xposed/LSPosed/Riru/Zygisk сигнатуры в maps (best-effort)
        boolean hookInMaps = ProcScan.selfMapsContains(
                "xposed", "lsposed", "edxp", "riru", "zygisk", "magisk", "substrate",
                "substrate-loader", "libsubstrate", "frida-agent"
        );
        details.add("maps(hooks/zygisk/riru)=" + hookInMaps);
        if (hookInMaps) hits.add("hook-maps");

        // 3) Frida-server порты (часто 27042/27043) — best-effort
        boolean fridaPort = LocalPort.isOpen(27042, 120) || LocalPort.isOpen(27043, 120);
        details.add("port(27042/27043)=" + fridaPort);
        if (fridaPort) hits.add("frida-port");

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
        details.add("unix_sockets(suspicious)=" + sockHit);
        if (sockHit) hits.add("socket-suspicious");

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
        details.add("proc_cmdline(suspicious)=" + procHit);
        if (procHit) hits.add("proc-suspicious");

        // 6.1) suspicious TCP ports in /proc/net/tcp (best-effort)
        boolean tcpHit = scanTcpPorts(27042, 27043, 23946, 23947);
        details.add("tcp_ports(suspicious)=" + tcpHit);
        if (tcpHit) hits.add("tcp-ports");

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

        if (!hits.isEmpty()) {
            boolean strong = dbg || tracerPid > 0 || fridaInMaps || fridaPort;
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
