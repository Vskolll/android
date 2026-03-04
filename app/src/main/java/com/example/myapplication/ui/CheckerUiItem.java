package com.example.myapplication.ui;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.CheckerStatus;

public class CheckerUiItem {
    public final String id;
    public final String title;
    public CheckerStatus status;
    public String reason;
    public String description;
    public boolean critical;

    public CheckerUiItem(String id, String title, CheckerResult r) {
        this.id = id;
        this.title = title;
        apply(r);
    }

    public void apply(CheckerResult r) {
        this.status = (r == null || r.status == null) ? CheckerStatus.UNKNOWN : r.status;
        this.reason = (r == null) ? "" : r.reason;
        this.description = (r == null) ? "" : r.description;
        this.critical = isCriticalId(this.id);
    }

    private boolean isCriticalId(String id) {
        return "root".equals(id) || "magisk_runtime".equals(id);
    }
}
