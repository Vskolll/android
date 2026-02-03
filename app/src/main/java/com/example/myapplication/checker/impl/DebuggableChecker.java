package com.example.myapplication.checker.impl;


import android.content.Context;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;

public class DebuggableChecker implements IChecker {

    @Override
    public String id() {
        return "debuggable";
    }

    @Override
    public String title() {
        return "App debuggable flag";
    }

    @Override
    public CheckerResult run(Context context) {
        // TODO: проверить флаги приложения / build config
        return CheckerResult.unknown(
                "Заглушка",
                "Проверка debuggable пока не реализована. Позже сюда: build flags, signature, anti-tamper."
        );
    }
}

