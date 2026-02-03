package com.example.myapplication.checker.util;

import java.net.InetSocketAddress;
import java.net.Socket;

public final class LocalPort {
    private LocalPort() {}

    public static boolean isOpen(int port, int timeoutMs) {
        Socket s = null;
        try {
            s = new Socket();
            s.connect(new InetSocketAddress("127.0.0.1", port), timeoutMs);
            return true;
        } catch (Throwable t) {
            return false;
        } finally {
            try { if (s != null) s.close(); } catch (Throwable ignored) {}
        }
    }
}

