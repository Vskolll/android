package com.example.myapplication.checker;

public class CheckerResult {
    public final CheckerStatus status;
    public final String reason;
    public final String description;

    public CheckerResult(CheckerStatus status, String reason, String description) {
        this.status = status;
        this.reason = reason;
        this.description = description;
    }

    public static CheckerResult unknown(String reason, String description) {
        return new CheckerResult(CheckerStatus.UNKNOWN, reason, description);
    }

    public static CheckerResult pass(String reason, String description) {
        return new CheckerResult(CheckerStatus.PASS, reason, description);
    }

    public static CheckerResult fail(String reason, String description) {
        return new CheckerResult(CheckerStatus.FAIL, reason, description);
    }
}
