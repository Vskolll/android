package com.example.myapplication.checker.impl;

import android.content.Context;
import android.os.Build;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;
import com.example.myapplication.checker.util.SystemProp;

public class FirmwareKeysCertificateChecker implements IChecker {

    @Override public String id() { return "fw_keys"; }

    @Override public String title() { return "Firmware keys / certificate"; }

    @Override
    public CheckerResult run(Context context) {
        String buildTags = Build.TAGS == null ? "" : Build.TAGS;
        String buildType = Build.TYPE == null ? "" : Build.TYPE;

        String roBuildTags = SystemProp.get("ro.build.tags");
        String roBuildType = SystemProp.get("ro.build.type");

        boolean testKeys = buildTags.contains("test-keys") || roBuildTags.contains("test-keys");
        boolean releaseKeys = buildTags.contains("release-keys") || roBuildTags.contains("release-keys");

        boolean nonUser = "userdebug".equalsIgnoreCase(buildType) || "eng".equalsIgnoreCase(buildType)
                || "userdebug".equalsIgnoreCase(roBuildType) || "eng".equalsIgnoreCase(roBuildType);

        String desc =
                "Build.TAGS=" + buildTags +
                        "\nBuild.TYPE=" + buildType +
                        "\nro.build.tags=" + roBuildTags +
                        "\nro.build.type=" + roBuildType;

        if (testKeys || nonUser) {
            return CheckerResult.fail(
                    "Non-production firmware keys",
                    "Обнаружены test-keys и/или тип сборки userdebug/eng — частый признак кастомной/отладочной прошивки.\n\n" + desc
            );
        }

        if (releaseKeys && "user".equalsIgnoreCase(buildType)) {
            return CheckerResult.pass(
                    "Release keys (user build)",
                    "Похоже на прод-сборку: release-keys + user.\n\n" + desc
            );
        }

        return CheckerResult.unknown(
                "Не удалось однозначно классифицировать",
                "Ключи/тип сборки не дают однозначного вывода.\n\n" + desc
        );
    }
}
