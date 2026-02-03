package com.example.myapplication.checker.impl;


import android.content.Context;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;

public class SelinuxChecker implements IChecker {

    @Override public String id() { return "selinux"; }
    @Override public String title() { return "SELinux enforcing"; }

    @Override
    public CheckerResult run(Context context) {
        // TODO: реализовать через getenforce / getprop (на разных девайсах по-разному)
        return CheckerResult.unknown(
                "Stub",
                "Заглушка. Позже: проверка enforcing/permissive."
        );
    }
}
