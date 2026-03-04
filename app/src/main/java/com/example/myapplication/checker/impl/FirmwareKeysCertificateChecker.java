package com.example.myapplication.checker.impl;

import android.content.Context;
import android.os.Build;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;
import com.example.myapplication.checker.util.SystemProp;

public class FirmwareKeysCertificateChecker implements IChecker {

    @Override public String id() { return "fw_keys"; }

    @Override public String title() { return "Ключи прошивки"; }

    @Override
    public CheckerResult run(Context context) {
        String buildTags = Build.TAGS == null ? "" : Build.TAGS.trim();
        String buildType = Build.TYPE == null ? "" : Build.TYPE.trim();

        String roBuildTags = SystemProp.get("ro.build.tags");
        String roBuildType = SystemProp.get("ro.build.type");
        String roBuildKeys = SystemProp.get("ro.build.keys");
        String roBuildFlavor = SystemProp.get("ro.build.flavor");

        boolean testKeys = buildTags.contains("test-keys") || roBuildTags.contains("test-keys");
        boolean releaseKeys = buildTags.contains("release-keys") || roBuildTags.contains("release-keys");
        boolean devKeys = buildTags.contains("dev-keys") || roBuildTags.contains("dev-keys");

        boolean nonUser = "userdebug".equalsIgnoreCase(buildType) || "eng".equalsIgnoreCase(buildType)
                || "userdebug".equalsIgnoreCase(roBuildType) || "eng".equalsIgnoreCase(roBuildType);

        String desc =
                "Build.TAGS=" + buildTags +
                        "\nBuild.TYPE=" + buildType +
                        "\nro.build.tags=" + roBuildTags +
                        "\nro.build.type=" + roBuildType +
                        "\nro.build.keys=" + roBuildKeys +
                        "\nro.build.flavor=" + roBuildFlavor;

        if (testKeys || devKeys || nonUser) {
            return CheckerResult.fail(
                    "Не‑прод сборка",
                    "Обнаружены test/dev‑keys и/или тип сборки userdebug/eng.\n\n" + desc
            );
        }

        if (releaseKeys && "user".equalsIgnoreCase(buildType)) {
            return CheckerResult.pass(
                    "Release keys",
                    "Сборка с release‑keys и типом user.\n\n" + desc
            );
        }

        if (buildTags.isEmpty() && roBuildTags.isEmpty() && roBuildType.isEmpty()) {
            return CheckerResult.unknown(
                    "Нет данных",
                    "Сигналы ключей/типа сборки недоступны.\n\n" + desc
            );
        }

        return CheckerResult.unknown(
                "Неоднозначно",
                "Ключи/тип сборки не дают однозначного вывода.\n\n" + desc
        );
    }
}
