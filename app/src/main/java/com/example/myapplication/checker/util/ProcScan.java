package com.example.myapplication.checker.util;


import java.io.BufferedReader;
import java.io.FileReader;

public final class ProcScan {
    private ProcScan() {}

    public static boolean selfMapsContains(String... needles) {
        return fileContains("/proc/self/maps", needles);
    }

    public static boolean fileContains(String path, String... needles) {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(path));
            String line;
            while ((line = br.readLine()) != null) {
                String lower = line.toLowerCase();
                for (String n : needles) {
                    if (n == null) continue;
                    if (lower.contains(n.toLowerCase())) return true;
                }
            }
            return false;
        } catch (Throwable t) {
            return false;
        } finally {
            try { if (br != null) br.close(); } catch (Throwable ignored) {}
        }
    }
}
