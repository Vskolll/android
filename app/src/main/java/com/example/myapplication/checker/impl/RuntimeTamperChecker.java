package com.example.myapplication.checker.impl;


import android.content.Context;
import android.os.Debug;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;
import com.example.myapplication.checker.util.LocalPort;
import com.example.myapplication.checker.util.ProcScan;

public class RuntimeTamperChecker implements IChecker {

    @Override public String id() { return "runtime_tamper"; }

    @Override public String title() { return "Runtime trigger / tamper"; }

    @Override
    public CheckerResult run(Context context) {
        // 1) Debugger (самый простой runtime trigger)
        boolean dbg = Debug.isDebuggerConnected() || Debug.waitingForDebugger();
        if (dbg) {
            return CheckerResult.fail(
                    "Debugger attached",
                    "Обнаружен подключенный дебаггер (Debug.isDebuggerConnected / waitingForDebugger)."
            );
        }

        // 2) Frida gadget / gum в memory maps (best-effort)
        boolean fridaInMaps = ProcScan.selfMapsContains("frida", "gum-js-loop", "libfrida", "gadget");
        if (fridaInMaps) {
            return CheckerResult.fail(
                    "Suspicious library in memory",
                    "В /proc/self/maps найдено совпадение по сигнатурам frida/gum/libfrida-gadget."
            );
        }

        // 3) Frida-server порты (часто 27042/27043) — best-effort
        boolean fridaPort = LocalPort.isOpen(27042, 120) || LocalPort.isOpen(27043, 120);
        if (fridaPort) {
            return CheckerResult.fail(
                    "Suspicious local port",
                    "Локальный порт 27042/27043 отвечает (частый признак frida-server)."
            );
        }

        // 4) Xposed/LSPosed классы — best-effort
        if (classExists("de.robv.android.xposed.XposedBridge")
                || classExists("de.robv.android.xposed.XC_MethodHook")
                || classExists("org.lsposed.lspd.core.Main")
                || classExists("io.github.lsposed.lspd.core.Main")) {
            return CheckerResult.fail(
                    "Hook framework detected",
                    "Найдены классы, похожие на Xposed/LSPosed."
            );
        }

        return CheckerResult.pass(
                "No runtime triggers",
                "Явных признаков дебаггера/Frida/Xposed не найдено (best-effort проверки)."
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
}

