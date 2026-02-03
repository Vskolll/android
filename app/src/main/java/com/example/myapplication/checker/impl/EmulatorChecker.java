package com.example.myapplication.checker.impl;

import android.content.Context;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;

public class EmulatorChecker implements IChecker {

    @Override
    public String id() {
        return "emulator";
    }

    @Override
    public String title() {
        return "Emulator detection";
    }

    @Override
    public CheckerResult run(Context context) {
        // TODO: эвристики эмулятора (Build.*, hardware, sensors, etc.)
        return CheckerResult.unknown(
                "Заглушка",
                "Проверка эмулятора пока не реализована. Позже: эвристики Build/HW/Sensors."
        );
    }
}
