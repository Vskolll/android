package com.example.myapplication.ui;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.CheckerStatus;

public class CheckerItem {
    public final String id;
    public final String title;

    public CheckerStatus status = CheckerStatus.UNKNOWN;
    public String reason = "Не запускалось";
    public String description = "Нажми ▶ чтобы прогнать проверки.";
    public boolean expanded = false;

    public CheckerItem(String id, String title) {
        this.id = id;
        this.title = title;
    }

    public void applyResult(CheckerResult r) {
        if (r == null) return;
        status = r.status;
        reason = r.reason;
        description = r.description;
    }
}
