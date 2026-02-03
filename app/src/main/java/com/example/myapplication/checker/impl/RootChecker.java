package com.example.myapplication.checker.impl;

import android.content.Context;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;

public class RootChecker implements IChecker {

    @Override
    public String id() {
        return "root";
    }

    @Override
    public String title() {
        return "Root detected";
    }

    @Override
    public CheckerResult run(Context context) {
        // TODO: тут будет реальная проверка
        return CheckerResult.unknown(
                "Заглушка",
                "Проверка root пока не реализована. Здесь будет список сигналов и итоговое решение."
        );
    }
}

