package com.example.myapplication.checker;

import com.example.myapplication.checker.impl.BootModeChecker;
import com.example.myapplication.checker.impl.BootloaderVerifiedBootChecker;

import java.util.Arrays;
import java.util.List;

public final class CheckerRegistry {
    private CheckerRegistry() {}

    public static List<IChecker> all() {
        return Arrays.asList(
                new BootloaderVerifiedBootChecker(),
                new BootModeChecker()
        );
    }
}
