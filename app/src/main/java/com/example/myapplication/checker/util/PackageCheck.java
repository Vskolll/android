package com.example.myapplication.checker.util;


import android.content.Context;
import android.content.pm.PackageManager;

public final class PackageCheck {
    private PackageCheck() {}

    public static boolean isInstalled(Context ctx, String pkg) {
        try {
            ctx.getPackageManager().getPackageInfo(pkg, 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        } catch (Throwable t) {
            return false;
        }
    }
}
