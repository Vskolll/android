package com.example.myapplication.checker;

import android.content.Context;

public interface IChecker {
    String id();
    String title();
    CheckerResult run(Context context);
}
