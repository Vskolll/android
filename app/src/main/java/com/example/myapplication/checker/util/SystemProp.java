package com.example.myapplication.checker.util;

import android.annotation.SuppressLint;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;

public final class SystemProp {
    private SystemProp() {}

    @SuppressLint("PrivateApi")
    public static String get(String key) {
        // 1) reflection android.os.SystemProperties.get(key, "")
        try {
            Class<?> sp = Class.forName("android.os.SystemProperties");
            Method get = sp.getMethod("get", String.class, String.class);
            String v = (String) get.invoke(null, key, "");
            return v == null ? "" : v.trim();
        } catch (Throwable ignored) {}

        // 2) fallback: getprop key
        try {
            Process p = new ProcessBuilder("getprop", key).redirectErrorStream(true).start();
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = br.readLine();
            br.close();
            return line == null ? "" : line.trim();
        } catch (Throwable ignored) {}

        return "";
    }

    public static String firstNonEmpty(String... vals) {
        if (vals == null) return "";
        for (String v : vals) {
            if (v != null) {
                String t = v.trim();
                if (!t.isEmpty()) return t;
            }
        }
        return "";
    }

    public static boolean isTrueish(String v) {
        if (v == null) return false;
        String t = v.trim().toLowerCase();
        return t.equals("1") || t.equals("true") || t.equals("yes") || t.equals("y");
    }

    public static boolean isFalseish(String v) {
        if (v == null) return false;
        String t = v.trim().toLowerCase();
        return t.equals("0") || t.equals("false") || t.equals("no") || t.equals("n");
    }
}
