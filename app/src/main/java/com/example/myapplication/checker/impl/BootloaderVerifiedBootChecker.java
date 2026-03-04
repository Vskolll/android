package com.example.myapplication.checker.impl;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.IChecker;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class BootloaderVerifiedBootChecker implements IChecker {

    private static final String ID = "bootloader_vb";
    private static final long CMD_TIMEOUT_MS = 250;

    // Android Key Attestation extension OID
    private static final String OID_ATTESTATION = "1.3.6.1.4.1.11129.2.1.17";
    private static final String FEATURE_STRONGBOX = "android.hardware.strongbox_keystore";

    // --- prop keys ---
    private static final String[] KEY_VERIFIED_BOOTSTATE = {
            "ro.boot.verifiedbootstate"
    };

    private static final String[] KEY_VBMETA_DEVICE_STATE = {
            "ro.boot.vbmeta.device_state",
            "ro.boot.device_state"
    };

    private static final String[] KEY_FLASH_LOCKED = {
            "ro.boot.flash.locked",
            "ro.boot.bootloader.locked",
            "ro.boot.locked"
    };

    private static final String[] KEY_VERITYMODE = {
            "ro.boot.veritymode"
    };

    private static final String[] KEY_AVB_VERSION = {
            "ro.boot.avb_version"
    };

    // --- kernel arg keys ---
    private static final String[] KERNEL_VERIFIED_BOOTSTATE = {
            "androidboot.verifiedbootstate"
    };

    private static final String[] KERNEL_VBMETA_DEVICE_STATE = {
            "androidboot.vbmeta.device_state",
            "androidboot.device_state"
    };

    private static final String[] KERNEL_FLASH_LOCKED = {
            "androidboot.flash.locked",
            "androidboot.bootloader.locked",
            "androidboot.locked"
    };

    @Override
    public String id() { return ID; }

    @Override
    public String title() { return "Загрузчик / Verified Boot"; }

    @Override
    public CheckerResult run(Context context) {

        MultiSourceReader r = new MultiSourceReader();

        Signal verifiedBootState = r.firstSignal(KEY_VERIFIED_BOOTSTATE, KERNEL_VERIFIED_BOOTSTATE);
        Signal vbmetaDeviceState = r.firstSignal(KEY_VBMETA_DEVICE_STATE, KERNEL_VBMETA_DEVICE_STATE);
        Signal flashLocked       = r.firstSignal(KEY_FLASH_LOCKED, KERNEL_FLASH_LOCKED);
        Signal verityMode        = r.firstSignal(KEY_VERITYMODE, new String[0]);
        Signal avbVersion        = r.firstSignal(KEY_AVB_VERSION, new String[0]);

        VerifiedBoot vbProps = VerifiedBoot.from(safeLower(verifiedBootState.value));
        LockState lockProps = LockState.from(safeLower(vbmetaDeviceState.value), safeLower(flashLocked.value));

        VerifiedBoot vb = vbProps;
        LockState lock = lockProps;

        // --- Attestation: ALWAYS try (for 2nd factor: certificate trust), but do not fail if StrongBox missing ---
        AttestationResult att = AttestationResult.tryFetch(context);
        boolean strongAtt = att != null && att.ok && att.strength == AttestationStrength.STRONG;
        boolean weakAtt   = att != null && att.ok && att.strength == AttestationStrength.WEAK;

        // If attestation is STRONG, prefer it over props (more truthful RootOfTrust)
        if (strongAtt) {
            if (att.deviceLocked != null) {
                lock = att.deviceLocked ? LockState.LOCKED : LockState.UNLOCKED;
            }
            if (att.verifiedBoot != null) {
                vb = att.verifiedBoot;
            }
        } else {
            // If weak attestation, only use it as fallback for UNKNOWN
            if (lock == LockState.UNKNOWN && att != null && att.ok && att.deviceLocked != null) {
                lock = att.deviceLocked ? LockState.LOCKED : LockState.UNLOCKED;
            }
            if (vb == VerifiedBoot.UNKNOWN && att != null && att.ok && att.verifiedBoot != null) {
                vb = att.verifiedBoot;
            }
        }

        // Mismatch note (useful)
        boolean vbMismatch = (att != null && att.ok && att.verifiedBoot != null && vbProps != VerifiedBoot.UNKNOWN && vbProps != att.verifiedBoot);

        // ------------------ CRITICAL FACTORS ------------------
        // Factor A: Bootloader unlocked  (critical)
        // Factor B: Verified Boot broken (ORANGE/RED) (critical)

        // 1) Verified Boot RED
        if (vb == VerifiedBoot.RED) {
            if (vbProps == VerifiedBoot.RED || strongAtt) {
                    return CheckerResult.fail(
                            "Verified Boot: RED",
                            buildDescription(r, verifiedBootState, vbmetaDeviceState, flashLocked, verityMode, avbVersion, att,
                                    (vbMismatch ? "Примечание: обнаружено несоответствие между ro.boot.* и attestation.\n\n" : "") +
                                            "Состояние RED означает нарушение целостности загрузки.")
                    );
                } else {
                    return CheckerResult.warn(
                            "Verified Boot: RED (неподтверждён)",
                            buildDescription(r, verifiedBootState, vbmetaDeviceState, flashLocked, verityMode, avbVersion, att,
                                    "Attestation сообщает RED, но источник software‑уровня.")
                    );
                }
        }

        // 2) Bootloader UNLOCKED
        if (lock == LockState.UNLOCKED) {
            if (lockProps == LockState.UNLOCKED || strongAtt) {
                return CheckerResult.fail(
                        "Bootloader: UNLOCKED",
                            buildDescription(r, verifiedBootState, vbmetaDeviceState, flashLocked, verityMode, avbVersion, att,
                                    (vbMismatch ? "Примечание: обнаружено несоответствие между ro.boot.* и attestation.\n\n" : "") +
                                            "Загрузчик разблокирован.")
                );
            } else {
                return CheckerResult.fail(
                        "Bootloader: UNLOCKED",
                        buildDescription(r, verifiedBootState, vbmetaDeviceState, flashLocked, verityMode, avbVersion, att,
                                "Attestation сообщает UNLOCKED, но источник software‑уровня.")
                );
            }
        }

        // 3) Verified Boot ORANGE
        if (vb == VerifiedBoot.ORANGE) {
            if (vbProps == VerifiedBoot.ORANGE || strongAtt) {
                    return CheckerResult.fail(
                            "Verified Boot: ORANGE",
                            buildDescription(r, verifiedBootState, vbmetaDeviceState, flashLocked, verityMode, avbVersion, att,
                                    (vbMismatch ? "Примечание: обнаружено несоответствие между ro.boot.* и attestation.\n\n" : "") +
                                            "ORANGE обычно означает unverified/modified boot.")
                    );
                } else {
                    return CheckerResult.warn(
                            "Verified Boot: ORANGE (неподтверждён)",
                            buildDescription(r, verifiedBootState, vbmetaDeviceState, flashLocked, verityMode, avbVersion, att,
                                    "Attestation сообщает ORANGE, но источник software‑уровня.")
                    );
                }
        }

        // ------------------ NON-CRITICAL / INFO STATES ------------------

        // 3.5) AOSP software attestation root (low trust)
        if (att != null && att.ok && att.isAospSoftwareRoot) {
            return CheckerResult.warn(
                    "AOSP software attestation root certificate",
                    buildDescription(r, verifiedBootState, vbmetaDeviceState, flashLocked, verityMode, avbVersion, att,
                            "Аттестация выполнена на software‑уровне (AOSP root). Такой результат можно подделать.")
            );
        }

        // 4) LOCKED + GREEN
        if (lock == LockState.LOCKED && vb == VerifiedBoot.GREEN) {
            if (strongAtt) {
                return CheckerResult.pass(
                        "LOCKED + GREEN",
                        buildDescription(r, verifiedBootState, vbmetaDeviceState, flashLocked, verityMode, avbVersion, att,
                                "LOCKED и Verified Boot = GREEN (подтверждено TEE/StrongBox).")
                );
            } else {
                return CheckerResult.warn(
                        "LOCKED + GREEN (без подтверждения)",
                        buildDescription(r, verifiedBootState, vbmetaDeviceState, flashLocked, verityMode, avbVersion, att,
                                (vbMismatch ? "Примечание: обнаружено несоответствие между ro.boot.* и attestation.\n\n" : "") +
                                        "LOCKED + GREEN без подтверждения TEE/StrongBox.")
                );
            }
        }

        // 5) LOCKED + YELLOW
        if (lock == LockState.LOCKED && vb == VerifiedBoot.YELLOW) {
            return CheckerResult.warn(
                    "LOCKED + YELLOW",
                    buildDescription(r, verifiedBootState, vbmetaDeviceState, flashLocked, verityMode, avbVersion, att,
                            (vbMismatch ? "Примечание: обнаружено несоответствие между ro.boot.* и attestation.\n\n" : "") +
                                    "Verified Boot = YELLOW — устройство использует кастомные ключи доверия.")
            );
        }

        // 6) GREEN, lock unknown
        if (vb == VerifiedBoot.GREEN && lock == LockState.UNKNOWN) {
            return CheckerResult.warn(
                    "GREEN (lock unknown)",
                    buildDescription(r, verifiedBootState, vbmetaDeviceState, flashLocked, verityMode, avbVersion, att,
                            (vbMismatch ? "Примечание: обнаружено несоответствие между ro.boot.* и attestation.\n\n" : "") +
                                    "Verified Boot = GREEN, но lock‑state не определён.")
            );
        }

        // 7) no signals
        if (vb == VerifiedBoot.UNKNOWN && lock == LockState.UNKNOWN) {
            return CheckerResult.unknown(
                    "Нет сигналов",
                    buildDescription(r, verifiedBootState, vbmetaDeviceState, flashLocked, verityMode, avbVersion, att,
                            "Не удалось извлечь сигналы Bootloader/Verified Boot.")
            );
        }

        // 8) fallback
        return CheckerResult.warn(
                "Смешанные сигналы",
                buildDescription(r, verifiedBootState, vbmetaDeviceState, flashLocked, verityMode, avbVersion, att,
                        (vbMismatch ? "Примечание: обнаружено несоответствие между ro.boot.* и attestation.\n\n" : "") +
                                "Комбинация сигналов неоднозначна.")
        );
    }

    // -------------------- Description --------------------

    private static String buildDescription(
            MultiSourceReader r,
            Signal verifiedBootState,
            Signal vbmetaDeviceState,
            Signal flashLocked,
            Signal verityMode,
            Signal avbVersion,
            AttestationResult att,
            String meaning
    ) {
        List<String> lines = new ArrayList<>();

        lines.add("Сигналы (значение • источник):");
        lines.add("• ro.boot.verifiedbootstate = " + valueOrUnknown(verifiedBootState.value) + "  • " + verifiedBootState.source);
        lines.add("• ro.boot.vbmeta.device_state = " + valueOrUnknown(vbmetaDeviceState.value) + "  • " + vbmetaDeviceState.source);
        lines.add("• ro.boot.flash.locked = " + valueOrUnknown(flashLocked.value) + "  • " + flashLocked.source);
        if (!isBlank(verityMode.value)) lines.add("• ro.boot.veritymode = " + verityMode.value.trim() + "  • " + verityMode.source);
        if (!isBlank(avbVersion.value)) lines.add("• ro.boot.avb_version = " + avbVersion.value.trim() + "  • " + avbVersion.source);

        lines.add("");
        lines.add("Интерпретация:");
        lines.add(meaning);

        lines.add("");
        lines.add("Диагностика чтения:");
        lines.addAll(r.debugLines());

        // Attestation diagnostics + cert factor
        if (att != null) {
            lines.add("");
            lines.add("Keystore Attestation (2-й фактор: доверие/сертификаты):");

            if (att.ok) {
                lines.add("• securityLevel = " + valueOrUnknown(att.securityLevel) + "  (надежность: " + att.strength.name() + ")");
                lines.add("• deviceLocked = " + (att.deviceLocked == null ? "unknown" : String.valueOf(att.deviceLocked)));
                lines.add("• verifiedBootState = " + (att.verifiedBoot == null ? "unknown" : att.verifiedBoot.name()));
                String rootHint = att.isAospSoftwareRoot
                        ? "AOSP software root (weak)"
                        : (att.strength == AttestationStrength.STRONG ? "Hardware-backed (TEE/StrongBox)" : "Non-AOSP software/unknown");
                lines.add("• rootHint = " + rootHint);
                if (!isBlank(att.attempt)) lines.add("• attempt = " + att.attempt);
                if (!isBlank(att.verifiedBootKeySha256)) lines.add("• verifiedBootKey SHA256 = " + att.verifiedBootKeySha256);
                if (!isBlank(att.verifiedBootHashSha256)) lines.add("• verifiedBootHash SHA256 = " + att.verifiedBootHashSha256);

                lines.add("");
                lines.add("Сертификаты attestation (цепочка):");
                for (int i = 0; i < att.chainSubjects.size(); i++) {
                    lines.add("• [" + i + "] " + att.chainSubjects.get(i));
                }
                if (!isBlank(att.rootSubject)) lines.add("• rootSubject = " + att.rootSubject);
                if (!isBlank(att.rootSha256))  lines.add("• rootSHA256 = " + att.rootSha256);

                if (att.isAospSoftwareRoot) {
                    lines.add("");
                    lines.add("ВНИМАНИЕ:");
                    lines.add("• Обнаружен AOSP software attestation root certificate.");
                    lines.add("• Это software-attestation: такой результат можно подделать → не является доказательством безопасности.");
                    lines.add("• Для высокой уверенности нужен TEE/StrongBox или проверка в bootloader/fastboot.");
                } else if (att.strength == AttestationStrength.WEAK) {
                    lines.add("");
                    lines.add("Примечание:");
                    lines.add("• Attestation на уровне software имеет низкую надежность по сравнению с TEE/StrongBox.");
                }

            } else {
                lines.add("• not available: " + valueOrUnknown(att.error));
            }
        }

        return join(lines, "\n");
    }

    // -------------------- Enums --------------------

    private enum VerifiedBoot {
        GREEN, YELLOW, ORANGE, RED, UNKNOWN;

        static VerifiedBoot from(String v) {
            if ("green".equals(v)) return GREEN;
            if ("yellow".equals(v)) return YELLOW;
            if ("orange".equals(v)) return ORANGE;
            if ("red".equals(v)) return RED;
            return UNKNOWN;
        }

        // 0 = VERIFIED, 1 = SELF_SIGNED, 2 = UNVERIFIED, 3 = FAILED
        static VerifiedBoot fromAttestation(int st) {
            switch (st) {
                case 0: return GREEN;
                case 1: return YELLOW;
                case 2: return ORANGE;
                case 3: return RED;
                default: return UNKNOWN;
            }
        }
    }

    private enum LockState {
        LOCKED, UNLOCKED, UNKNOWN;

        static LockState from(String vbmetaDeviceState, String flashLocked) {
            if ("locked".equals(vbmetaDeviceState)) return LOCKED;
            if ("unlocked".equals(vbmetaDeviceState)) return UNLOCKED;

            if ("1".equals(flashLocked) || "true".equals(flashLocked) || "yes".equals(flashLocked)) return LOCKED;
            if ("0".equals(flashLocked) || "false".equals(flashLocked) || "no".equals(flashLocked)) return UNLOCKED;

            return UNKNOWN;
        }
    }

    private enum AttestationStrength {
        STRONG, WEAK
    }

    // -------------------- Signal + Reader --------------------

    private static final class Signal {
        final String value;
        final String source;
        Signal(String value, String source) {
            this.value = value == null ? "" : value;
            this.source = source == null ? "unknown" : source;
        }
    }

    private static final class MultiSourceReader {
        private final Map<String, String> cache = new LinkedHashMap<>();
        private final List<String> debug = new ArrayList<>();

        Signal firstSignal(String[] propKeys, String[] androidbootKeys) {
            for (String k : propKeys) {
                String v = getPropertyBestEffort(k);
                if (!isBlank(v)) return new Signal(v.trim(), "prop(" + k + ")");
            }
            for (String k : androidbootKeys) {
                String v = readKernelArgBestEffort(k);
                if (!isBlank(v)) return new Signal(v.trim(), "kernel(" + k + ")");
            }
            return new Signal("", "not_found");
        }

        List<String> debugLines() {
            if (!debug.isEmpty()) return debug;
            List<String> x = new ArrayList<>();
            x.add("• источники: SystemProperties → getprop → /proc/cmdline → /proc/bootconfig → bootargs");
            return x;
        }

        private String getPropertyBestEffort(String key) {
            if (cache.containsKey(key)) return cache.get(key);

            String v1 = getSystemPropertyReflection(key, "");
            if (!isBlank(v1)) { cache.put(key, v1); return v1; }

            String v2 = getpropCmd(key);
            if (!isBlank(v2)) { cache.put(key, v2); return v2; }

            cache.put(key, "");
            return "";
        }

        private String readKernelArgBestEffort(String androidbootKey) {
            String v = getFromCmdline(androidbootKey);
            if (!isBlank(v)) return v;

            v = getFromBootconfig(androidbootKey);
            if (!isBlank(v)) return v;

            return getFromBootargs(androidbootKey);
        }

        private String getSystemPropertyReflection(String key, String def) {
            try {
                Class<?> sp = Class.forName("android.os.SystemProperties");
                Method m = sp.getMethod("get", String.class, String.class);
                Object out = m.invoke(null, key, def);
                String v = (out == null) ? def : String.valueOf(out).trim();
                if (!isBlank(v)) debug.add("• SystemProperties: " + key + " = " + v);
                return v;
            } catch (Throwable t) {
                return def;
            }
        }

        private String getpropCmd(String key) {
            BufferedReader br = null;
            Process p = null;
            try {
                p = new ProcessBuilder("sh", "-c", "getprop " + escapeShellArg(key))
                        .redirectErrorStream(true).start();

                boolean ok = p.waitFor(CMD_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                if (!ok) { try { p.destroy(); } catch (Throwable ignored) {} return ""; }

                br = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String line = br.readLine();
                if (line == null) return "";
                String v = line.trim();
                if (!isBlank(v)) debug.add("• getprop: " + key + " = " + v);
                return v;
            } catch (Throwable t) {
                return "";
            } finally {
                try { if (br != null) br.close(); } catch (Throwable ignored) {}
                try { if (p != null) p.destroy(); } catch (Throwable ignored) {}
            }
        }

        private static String getFromCmdline(String androidbootKey) {
            File f = new File("/proc/cmdline");
            if (!f.canRead()) return "";
            BufferedReader br = null;
            try {
                br = new BufferedReader(new FileReader(f));
                String line = br.readLine();
                if (line == null || line.trim().isEmpty()) return "";

                String prefix = androidbootKey + "=";
                String[] parts = line.split(" ");
                for (String p : parts) {
                    if (p.startsWith(prefix)) return p.substring(prefix.length()).trim();
                }
                return "";
            } catch (Throwable t) {
                return "";
            } finally {
                try { if (br != null) br.close(); } catch (Throwable ignored) {}
            }
        }

        private static String getFromBootconfig(String androidbootKey) {
            File f = new File("/proc/bootconfig");
            if (!f.canRead()) return "";

            BufferedReader br = null;
            try {
                br = new BufferedReader(new FileReader(f));
                String line;
                String prefix = androidbootKey + "=";
                while ((line = br.readLine()) != null) {
                    line = line.trim();
                    if (line.startsWith(prefix)) {
                        String v = line.substring(prefix.length()).trim();
                        if (v.startsWith("\"") && v.endsWith("\"") && v.length() >= 2) {
                            v = v.substring(1, v.length() - 1);
                        }
                        return v.trim();
                    }
                }
                return "";
            } catch (Throwable t) {
                return "";
            } finally {
                try { if (br != null) br.close(); } catch (Throwable ignored) {}
            }
        }

        private static String getFromBootargs(String androidbootKey) {
            File f = new File("/sys/firmware/devicetree/base/chosen/bootargs");
            if (!f.canRead()) return "";

            FileInputStream in = null;
            try {
                in = new FileInputStream(f);
                byte[] buf = new byte[8192];
                int n = in.read(buf);
                if (n <= 0) return "";

                int end = 0;
                for (; end < n; end++) if (buf[end] == 0) break;

                String bootargs = new String(buf, 0, end);
                if (isBlank(bootargs)) return "";

                String prefix = androidbootKey + "=";
                String[] parts = bootargs.split(" ");
                for (String p : parts) {
                    if (p.startsWith(prefix)) return p.substring(prefix.length()).trim();
                }
                return "";
            } catch (Throwable t) {
                return "";
            } finally {
                try { if (in != null) in.close(); } catch (Throwable ignored) {}
            }
        }

        private static String escapeShellArg(String s) {
            if (s == null) return "";
            return "'" + s.replace("'", "'\\''") + "'";
        }
    }

    // -------------------- Keystore Attestation (cascade + certs) --------------------

    private static final class AttestationResult {
        final boolean ok;
        final Boolean deviceLocked;           // null if not found
        final VerifiedBoot verifiedBoot;      // null if not found
        final String securityLevel;           // tee/strongbox/software
        final AttestationStrength strength;   // STRONG if TEE/StrongBox && not AOSP software root

        final boolean isAospSoftwareRoot;
        final List<String> chainSubjects;
        final String rootSubject;
        final String rootSha256;
        final String verifiedBootKeySha256;
        final String verifiedBootHashSha256;

        final String attempt;                // which attempt succeeded
        final String error;

        private AttestationResult(boolean ok,
                                  Boolean deviceLocked,
                                  VerifiedBoot vb,
                                  String sec,
                                  AttestationStrength strength,
                                  boolean isAospSoftwareRoot,
                                  List<String> chainSubjects,
                                  String rootSubject,
                                  String rootSha256,
                                  String verifiedBootKeySha256,
                                  String verifiedBootHashSha256,
                                  String attempt,
                                  String error) {
            this.ok = ok;
            this.deviceLocked = deviceLocked;
            this.verifiedBoot = vb;
            this.securityLevel = sec == null ? "" : sec;
            this.strength = strength == null ? AttestationStrength.WEAK : strength;
            this.isAospSoftwareRoot = isAospSoftwareRoot;
            this.chainSubjects = chainSubjects == null ? new ArrayList<String>() : chainSubjects;
            this.rootSubject = rootSubject == null ? "" : rootSubject;
            this.rootSha256 = rootSha256 == null ? "" : rootSha256;
            this.verifiedBootKeySha256 = verifiedBootKeySha256 == null ? "" : verifiedBootKeySha256;
            this.verifiedBootHashSha256 = verifiedBootHashSha256 == null ? "" : verifiedBootHashSha256;
            this.attempt = attempt == null ? "" : attempt;
            this.error = error == null ? "" : error;
        }

        static AttestationResult tryFetch(Context ctx) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
                return new AttestationResult(false, null, null, "", AttestationStrength.WEAK,
                        false, null, "", "", "", "", "", "API<24 (attestation unsupported)");
            }

            boolean hasStrongboxFeature = false;
            if (Build.VERSION.SDK_INT >= 28 && ctx != null) {
                try {
                    PackageManager pm = ctx.getPackageManager();
                    hasStrongboxFeature = pm != null && pm.hasSystemFeature(FEATURE_STRONGBOX);
                } catch (Throwable ignored) {}
            }

            Attempt[] attempts = new Attempt[] {
                    // 1) StrongBox EC (if feature exists) — if fails, fallback
                    new Attempt(KeyProperties.KEY_ALGORITHM_EC, true, hasStrongboxFeature, "EC/StrongBox"),
                    // 2) TEE/Software EC
                    new Attempt(KeyProperties.KEY_ALGORITHM_EC, false, true, "EC/default"),
                    // 3) TEE/Software RSA fallback (на некоторых девайсах EC капризничает)
                    new Attempt(KeyProperties.KEY_ALGORITHM_RSA, false, true, "RSA/default"),
            };

            String lastErr = "";

            for (Attempt a : attempts) {
                if (!a.enabled) continue;

                String alias = "vb_att_" + System.currentTimeMillis() + "_" + a.name.replace("/", "_");
                try {
                    byte[] challenge = new byte[16];
                    new SecureRandom().nextBytes(challenge);

                    KeyPairGenerator kpg = KeyPairGenerator.getInstance(a.algorithm, "AndroidKeyStore");

                    KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(
                            alias,
                            KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
                    ).setAttestationChallenge(challenge)
                            .setUserAuthenticationRequired(false);

                    if (KeyProperties.KEY_ALGORITHM_EC.equals(a.algorithm)) {
                        b.setDigests(KeyProperties.DIGEST_SHA256);
                    } else {
                        b.setKeySize(2048);
                        b.setDigests(KeyProperties.DIGEST_SHA256);
                        b.setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1);
                    }

                    // StrongBox only if requested; use reflection to avoid hard API requirements
                    if (a.strongbox && Build.VERSION.SDK_INT >= 28) {
                        try {
                            Method m = KeyGenParameterSpec.Builder.class.getMethod("setIsStrongBoxBacked", boolean.class);
                            m.invoke(b, true);
                        } catch (Throwable ignored) {}
                    }

                    kpg.initialize(b.build());
                    kpg.generateKeyPair();

                    KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
                    ks.load(null);

                    Certificate[] chain = ks.getCertificateChain(alias);
                    if (chain == null || chain.length == 0 || !(chain[0] instanceof X509Certificate)) {
                        cleanupKey(alias);
                        lastErr = "no certificate chain";
                        continue;
                    }

                    // gather chain subjects + root
                    List<String> subjects = new ArrayList<>();
                    X509Certificate root = null;
                    for (Certificate c : chain) {
                        if (c instanceof X509Certificate) {
                            X509Certificate xc = (X509Certificate) c;
                            subjects.add(xc.getSubjectX500Principal().getName());
                            root = xc; // last = root
                        }
                    }

                    String rootSubject = root != null ? root.getSubjectX500Principal().getName() : "";
                    String rootSha256 = root != null ? sha256Fingerprint(root.getEncoded()) : "";
                    boolean aospRoot = looksLikeAospSoftwareRoot(rootSubject);

                    X509Certificate leaf = (X509Certificate) chain[0];
                    byte[] ext = leaf.getExtensionValue(OID_ATTESTATION);
                    if (ext == null || ext.length == 0) {
                        cleanupKey(alias);
                        lastErr = "attestation extension missing";
                        continue;
                    }

                    AttestationParsed parsed = AttestationParsed.parseFromExtension(ext);
                    cleanupKey(alias);

                    if (parsed == null) {
                        lastErr = "attestation parse failed";
                        continue;
                    }

                    VerifiedBoot vb = (parsed.verifiedBootState == null)
                            ? null
                            : VerifiedBoot.fromAttestation(parsed.verifiedBootState);

                    String sec = parsed.securityLevel;

                    AttestationStrength strength = computeStrength(sec, aospRoot);

                    return new AttestationResult(true,
                            parsed.deviceLocked,
                            vb,
                            sec,
                            strength,
                            aospRoot,
                            subjects,
                            rootSubject,
                            rootSha256,
                            sha256Hex(parsed.verifiedBootKey),
                            sha256Hex(parsed.verifiedBootHash),
                            a.name,
                            "");

                } catch (Throwable t) {
                    cleanupKey(alias);

                    // StrongBox failures are normal on devices without SB; just fallback
                    lastErr = t.getClass().getSimpleName() + ": " + safeMsg(t.getMessage());
                }
            }

            return new AttestationResult(false, null, null, "", AttestationStrength.WEAK,
                    false, null, "", "", "", "", "", lastErr.isEmpty() ? "attestation unavailable" : lastErr);
        }

        private static AttestationStrength computeStrength(String securityLevel, boolean aospSoftwareRoot) {
            String s = safeLower(securityLevel);
            if (aospSoftwareRoot) return AttestationStrength.WEAK;
            if ("tee".equals(s) || "strongbox".equals(s)) return AttestationStrength.STRONG;
            return AttestationStrength.WEAK;
        }

        private static boolean looksLikeAospSoftwareRoot(String subjectDn) {
            if (isBlank(subjectDn)) return false;
            String s = subjectDn.toLowerCase(Locale.US);
            return s.contains("software attestation")
                    || s.contains("aosp")
                    || s.contains("android open source project")
                    || s.contains("android keystore software attestation root");
        }

        private static String sha256Fingerprint(byte[] der) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] dig = md.digest(der);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < dig.length; i++) {
                    if (i > 0) sb.append(":");
                    String h = Integer.toHexString(dig[i] & 0xFF).toUpperCase(Locale.US);
                    if (h.length() == 1) sb.append("0");
                    sb.append(h);
                }
                return sb.toString();
            } catch (Throwable t) {
                return "";
            }
        }

        private static String sha256Hex(byte[] data) {
            if (data == null || data.length == 0) return "";
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] dig = md.digest(data);
                StringBuilder sb = new StringBuilder();
                for (byte b : dig) {
                    String h = Integer.toHexString(b & 0xFF).toUpperCase(Locale.US);
                    if (h.length() == 1) sb.append("0");
                    sb.append(h);
                }
                return sb.toString();
            } catch (Throwable t) {
                return "";
            }
        }

        private static void cleanupKey(String alias) {
            try {
                KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
                ks.load(null);
                if (ks.containsAlias(alias)) ks.deleteEntry(alias);
            } catch (Throwable ignored) {}
        }

        private static String safeMsg(String s) {
            return s == null ? "" : s;
        }

        private static final class Attempt {
            final String algorithm;
            final boolean strongbox;
            final boolean enabled;
            final String name;

            Attempt(String algorithm, boolean strongbox, boolean enabled, String name) {
                this.algorithm = algorithm;
                this.strongbox = strongbox;
                this.enabled = enabled;
                this.name = name;
            }
        }
    }

    private static final class AttestationParsed {
        final Boolean deviceLocked;      // RootOfTrust.deviceLocked
        final Integer verifiedBootState; // RootOfTrust.verifiedBootState (0..3)
        final String securityLevel;      // software/tee/strongbox (best-effort)
        final byte[] verifiedBootKey;    // RootOfTrust.verifiedBootKey
        final byte[] verifiedBootHash;   // optional RootOfTrust.verifiedBootHash

        private AttestationParsed(Boolean deviceLocked,
                                  Integer verifiedBootState,
                                  String securityLevel,
                                  byte[] verifiedBootKey,
                                  byte[] verifiedBootHash) {
            this.deviceLocked = deviceLocked;
            this.verifiedBootState = verifiedBootState;
            this.securityLevel = securityLevel == null ? "" : securityLevel;
            this.verifiedBootKey = verifiedBootKey;
            this.verifiedBootHash = verifiedBootHash;
        }

        static AttestationParsed parseFromExtension(byte[] extValueDerOctetString) {
            try {
                // extValue is DER OCTET STRING wrapping KeyDescription (DER)
                Der.Node outer = Der.parse(extValueDerOctetString);
                if (outer == null || outer.tag != 0x04) return null;
                byte[] keyDescDer = outer.value;

                Der.Node keyDesc = Der.parse(keyDescDer);
                if (keyDesc == null || keyDesc.tag != 0x30 || keyDesc.children.size() < 8) return null;

                // indices: 0 attVer (int), 1 attSecLevel (enum), 2 kmVer, 3 kmSecLevel, 4 chall, 5 uniqueId, 6 swEnf, 7 teeEnf
                Der.Node attSec = keyDesc.children.get(1);
                Der.Node kmSec  = keyDesc.children.get(3);

                String sec = "unknown";
                Integer secVal = Der.readEnum(attSec);
                Integer kmVal  = Der.readEnum(kmSec);
                Integer pick = (kmVal != null) ? kmVal : secVal;

                if (pick != null) {
                    // 0 software, 1 tee, 2 strongbox
                    if (pick == 0) sec = "software";
                    else if (pick == 1) sec = "tee";
                    else if (pick == 2) sec = "strongbox";
                }

                Der.Node sw  = keyDesc.children.get(6);
                Der.Node tee = keyDesc.children.get(7);

                RootOfTrust rot = findRootOfTrust(tee);
                if (rot == null) rot = findRootOfTrust(sw);

                if (rot == null) return new AttestationParsed(null, null, sec, null, null);
                return new AttestationParsed(rot.deviceLocked, rot.verifiedBootState, sec, rot.verifiedBootKey, rot.verifiedBootHash);
            } catch (Throwable t) {
                return null;
            }
        }

        private static RootOfTrust findRootOfTrust(Der.Node authList) {
            if (authList == null) return null;
            if (authList.tag != 0x30) return null; // SEQUENCE

            // context-specific tag number 704 (rootOfTrust)
            for (Der.Node n : authList.children) {
                if (n.tagClass == Der.TAG_CLASS_CONTEXT && n.tagNo == 704) {
                    Der.Node inner = (n.children.size() == 1) ? n.children.get(0) : n;

                    if (inner.tag != 0x30) {
                        Der.Node trySeq = Der.parse(n.value);
                        if (trySeq != null && trySeq.tag == 0x30) inner = trySeq;
                        else return null;
                    }

                    Boolean deviceLocked = null;
                    Integer verifiedBootState = null;
                    byte[] verifiedBootKey = null;
                    byte[] verifiedBootHash = null;

                    for (Der.Node c : inner.children) {
                        if (deviceLocked == null && c.tag == 0x01) deviceLocked = Der.readBoolean(c);
                        if (verifiedBootState == null && c.tag == 0x0A) verifiedBootState = Der.readEnum(c);
                        if (c.tag == 0x04) {
                            if (verifiedBootKey == null) verifiedBootKey = Der.readOctets(c);
                            else if (verifiedBootHash == null) verifiedBootHash = Der.readOctets(c);
                        }
                    }
                    return new RootOfTrust(deviceLocked, verifiedBootState, verifiedBootKey, verifiedBootHash);
                }
            }
            return null;
        }

        private static final class RootOfTrust {
            final Boolean deviceLocked;
            final Integer verifiedBootState;
            final byte[] verifiedBootKey;
            final byte[] verifiedBootHash;

            RootOfTrust(Boolean deviceLocked,
                        Integer verifiedBootState,
                        byte[] verifiedBootKey,
                        byte[] verifiedBootHash) {
                this.deviceLocked = deviceLocked;
                this.verifiedBootState = verifiedBootState;
                this.verifiedBootKey = verifiedBootKey;
                this.verifiedBootHash = verifiedBootHash;
            }
        }
    }

    /**
     * Мини-DER парсер: хватает для вытягивания RootOfTrust из attestation.
     */
    private static final class Der {

        static final int TAG_CLASS_UNIVERSAL = 0;
        static final int TAG_CLASS_APPLICATION = 1;
        static final int TAG_CLASS_CONTEXT = 2;
        static final int TAG_CLASS_PRIVATE = 3;

        static final class Node {
            final int tag;         // raw first-tag byte
            final int tagClass;    // 0..3
            final boolean constructed;
            final int tagNo;       // decoded tag number
            final byte[] value;    // raw value bytes
            final List<Node> children = new ArrayList<>();

            Node(int tag, int tagClass, boolean constructed, int tagNo, byte[] value) {
                this.tag = tag;
                this.tagClass = tagClass;
                this.constructed = constructed;
                this.tagNo = tagNo;
                this.value = value == null ? new byte[0] : value;
            }
        }

        static Node parse(byte[] data) {
            if (data == null || data.length < 2) return null;
            Reader r = new Reader(data);
            return r.readNode();
        }

        static Boolean readBoolean(Node n) {
            if (n == null || n.value.length < 1) return null;
            return n.value[0] != 0;
        }

        static Integer readEnum(Node n) {
            return readInt(n);
        }

        static Integer readInt(Node n) {
            if (n == null || n.value.length == 0) return null;
            int v = 0;
            for (byte b : n.value) v = (v << 8) | (b & 0xFF);
            return v;
        }

        static byte[] readOctets(Node n) {
            if (n == null || n.tag != 0x04) return null;
            return n.value;
        }

        private static final class Reader {
            final byte[] d;
            int p = 0;

            Reader(byte[] d) { this.d = d; }

            Node readNode() {
                if (p >= d.length) return null;

                int first = readU8();
                int tagClass = (first >> 6) & 0x03;
                boolean constructed = ((first & 0x20) != 0);
                int tagNo = (first & 0x1F);

                // high-tag-number form
                if (tagNo == 0x1F) {
                    tagNo = 0;
                    int b;
                    do {
                        b = readU8();
                        tagNo = (tagNo << 7) | (b & 0x7F);
                    } while ((b & 0x80) != 0 && p < d.length);
                }

                int len = readLength();
                if (len < 0 || p + len > d.length) return null;

                byte[] value = new byte[len];
                System.arraycopy(d, p, value, 0, len);
                p += len;

                Node n = new Node(first & 0xFF, tagClass, constructed, tagNo, value);

                if (constructed) {
                    Reader cr = new Reader(value);
                    Node child;
                    while ((child = cr.readNode()) != null) {
                        n.children.add(child);
                        if (cr.p >= cr.d.length) break;
                    }
                }
                return n;
            }

            int readLength() {
                if (p >= d.length) return -1;
                int b = readU8();
                if ((b & 0x80) == 0) return b;

                int count = b & 0x7F;
                if (count == 0 || count > 4) return -1;
                if (p + count > d.length) return -1;

                int len = 0;
                for (int i = 0; i < count; i++) {
                    len = (len << 8) | readU8();
                }
                return len;
            }

            int readU8() {
                return d[p++] & 0xFF;
            }
        }
    }

    // -------------------- Helpers --------------------

    private static String safeLower(String s) {
        return s == null ? "" : s.trim().toLowerCase(Locale.US);
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    private static String valueOrUnknown(String s) {
        return isBlank(s) ? "unknown" : s.trim();
    }

    private static String join(List<String> xs, String sep) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < xs.size(); i++) {
            if (i > 0) sb.append(sep);
            sb.append(xs.get(i));
        }
        return sb.toString();
    }
}
