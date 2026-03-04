package com.example.myapplication.checker;

import androidx.annotation.Nullable;

import com.example.myapplication.BuildConfig;
import com.example.myapplication.checker.impl.AdbEnabledChecker;
import com.example.myapplication.checker.impl.BootModeChecker;
import com.example.myapplication.checker.impl.BootloaderVerifiedBootChecker;
import com.example.myapplication.checker.impl.DebuggableChecker;
import com.example.myapplication.checker.impl.DeveloperOptionsChecker;
import com.example.myapplication.checker.impl.EmulatorChecker;
import com.example.myapplication.checker.impl.FirmwareIntegrityChecker;
import com.example.myapplication.checker.impl.FirmwareKeysCertificateChecker;
import com.example.myapplication.checker.impl.MagiskFlagChecker;
import com.example.myapplication.checker.impl.MagiskRuntimeChecker;
import com.example.myapplication.checker.impl.RootChecker;
import com.example.myapplication.checker.impl.RuntimeTamperChecker;
import com.example.myapplication.checker.impl.SelinuxChecker;
import com.example.myapplication.checker.impl.UnknownSourcesChecker;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class CheckerRegistry {

    private static final List<IChecker> CHECKERS;

    static {
        List<IChecker> list = new ArrayList<>();

        // Базовый список чекеров (по мере готовности — реализуем детально)
        list.add(new BootloaderVerifiedBootChecker());
        list.add(new FirmwareIntegrityChecker());
        list.add(new FirmwareKeysCertificateChecker());
        list.add(new RootChecker());
        list.add(new MagiskFlagChecker());
        list.add(new MagiskRuntimeChecker());
        list.add(new AdbEnabledChecker());
        list.add(new DeveloperOptionsChecker());
        if (!BuildConfig.DEBUG) {
            list.add(new SelinuxChecker());
        }
        list.add(new RuntimeTamperChecker());
        list.add(new BootModeChecker());
        if (!BuildConfig.DEBUG) {
            list.add(new DebuggableChecker());
        }

        CHECKERS = Collections.unmodifiableList(list);
    }

    private CheckerRegistry() {}

    public static List<IChecker> all() {
        return CHECKERS;
    }

    @Nullable
    public static IChecker byId(String id) {
        if (id == null) return null;
        for (IChecker c : CHECKERS) {
            if (id.equals(c.id())) return c;
        }
        return null;
    }
}
