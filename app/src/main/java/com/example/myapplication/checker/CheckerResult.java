package com.example.myapplication.checker;

public class CheckerResult {

    public final CheckerStatus status;
    public final String reason;
    public final String description;

    public CheckerResult(CheckerStatus status, String reason, String description) {
        this.status = status == null ? CheckerStatus.UNKNOWN : status;
        this.reason = reason == null ? "" : reason;
        this.description = description == null ? "" : description;
    }

    public static CheckerResult pass(String reason, String description) {
        return new CheckerResult(CheckerStatus.PASS, reason, description);
    }

    public static CheckerResult warn(String reason, String description) {
        return new CheckerResult(CheckerStatus.WARN, reason, description);
    }

    public static CheckerResult fail(String reason, String description) {
        return new CheckerResult(CheckerStatus.FAIL, reason, description);
    }

    public static CheckerResult unknown(String reason, String description) {
        return new CheckerResult(CheckerStatus.UNKNOWN, reason, description);
    }
}
