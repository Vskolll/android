package com.example.myapplication.ui;

import android.annotation.SuppressLint;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.provider.Settings;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import com.example.myapplication.R;
import com.example.myapplication.auth.SessionManager;
import com.google.android.material.button.MaterialButton;

import org.json.JSONObject;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Locale;
import java.util.UUID;

public class CodeEntryActivity extends AppCompatActivity {

    private static final String[] BASE_URLS = {
            "https://api.pro-ver-ka.ru",
            "https://pro-ver-ka.com"
    };
    private static final String APP_SECRET = "wefqfqf1f134gref1dw";
    private static final String DEVICE_PREF = "v7_device";
    private static final String KEY_FALLBACK_DEVICE_ID = "fallback_device_id";

    private EditText etCode;
    private MaterialButton btnActivate;
    private ProgressBar pbActivate;
    private boolean activationRunning = false;
    private String lastAutoActivationCode = "";

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_code_entry);

        etCode = findViewById(R.id.etCode);
        btnActivate = findViewById(R.id.btnActivate);
        pbActivate = findViewById(R.id.pbActivate);

        btnActivate.setOnClickListener(v -> {
            String code = etCode.getText() == null ? "" : etCode.getText().toString();
            verifyCode(code, false);
        });

        handleActivationIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleActivationIntent(intent);
    }

    private void handleActivationIntent(@Nullable Intent intent) {
        String code = extractActivationCode(intent);
        if (code.isEmpty()) return;
        etCode.setText(code);
        etCode.setSelection(code.length());
        if (code.equals(lastAutoActivationCode)) return;
        lastAutoActivationCode = code;
        verifyCode(code, true);
    }

    private String extractActivationCode(@Nullable Intent intent) {
        if (intent == null || intent.getData() == null) return "";
        Uri uri = intent.getData();
        String code = uri.getQueryParameter("code");
        if (isActivationCode(code)) {
            return normalizeActivationCode(code);
        }
        java.util.List<String> segments = uri.getPathSegments();
        if (segments != null && !segments.isEmpty()) {
            String last = segments.get(segments.size() - 1);
            if (isActivationCode(last)) {
                return normalizeActivationCode(last);
            }
        }
        return "";
    }

    private void verifyCode(String code, boolean fromLink) {
        if (activationRunning) return;
        String cleanCode = normalizeActivationCode(code);
        if (cleanCode.isEmpty()) {
            Toast.makeText(this, "Введите код", Toast.LENGTH_SHORT).show();
            return;
        }
        if (fromLink) {
            Toast.makeText(this, "Код получен из ссылки. Активирую...", Toast.LENGTH_SHORT).show();
        }
        activationRunning = true;
        setLoading(btnActivate, pbActivate, true);
        new VerifyTask(cleanCode, getDeviceIdSafe()).execute();
    }

    private boolean isActivationCode(@Nullable String code) {
        String cleanCode = normalizeActivationCode(code);
        return cleanCode.startsWith("V7-") && cleanCode.length() >= 8;
    }

    private String normalizeActivationCode(@Nullable String code) {
        if (code == null) return "";
        return code.trim().replace(" ", "").toUpperCase(Locale.US);
    }

    @SuppressLint("HardwareIds")
    private String getDeviceIdSafe() {
        String androidId = Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);
        if (androidId != null && !androidId.trim().isEmpty()) {
            return androidId.trim();
        }

        SharedPreferences sp = getSharedPreferences(DEVICE_PREF, MODE_PRIVATE);
        String fallback = sp.getString(KEY_FALLBACK_DEVICE_ID, "");
        if (fallback == null || fallback.trim().isEmpty()) {
            fallback = "install-" + UUID.randomUUID();
            sp.edit().putString(KEY_FALLBACK_DEVICE_ID, fallback).apply();
        }
        return fallback;
    }

    private class VerifyTask extends AsyncTask<Void, Void, String> {
        private final String code;
        private final String deviceId;
        private String token = "";
        private long expiresAt = 0;
        private String errorMessage = "";
        private int httpStatus = -1;

        VerifyTask(String code, String deviceId) {
            this.code = code;
            this.deviceId = deviceId;
        }

        @Override
        protected String doInBackground(Void... voids) {
            String lastResult = "error";
            for (String baseUrl : BASE_URLS) {
                String result = requestVerify(baseUrl);
                if ("ok".equals(result)) {
                    return result;
                }
                lastResult = result;
                if ("http_error".equals(result) && (httpStatus < 500 || httpStatus >= 600)) {
                    return result;
                }
            }
            return lastResult;
        }

        private String requestVerify(String baseUrl) {
            try {
                URL url = new URL(baseUrl + "/verify");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("X-App-Secret", APP_SECRET);
                conn.setDoOutput(true);
                conn.setConnectTimeout(8000);
                conn.setReadTimeout(8000);

                JSONObject body = new JSONObject();
                body.put("code", code);
                body.put("device_id", deviceId);

                BufferedOutputStream os = new BufferedOutputStream(conn.getOutputStream());
                os.write(body.toString().getBytes());
                os.flush();
                os.close();

                int status = conn.getResponseCode();
                httpStatus = status;
                BufferedReader br = new BufferedReader(new InputStreamReader(
                        status >= 200 && status < 300 ? conn.getInputStream() : conn.getErrorStream()
                ));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) sb.append(line);
                br.close();
                conn.disconnect();

                if (status >= 200 && status < 300) {
                    JSONObject json = new JSONObject(sb.toString());
                    token = json.optString("session_token", "");
                    expiresAt = json.optLong("expires_at", 0L);
                    return "ok";
                }
                errorMessage = sb.toString();
                return "http_error";
            } catch (Throwable t) {
                errorMessage = t.getClass().getSimpleName();
                return "error";
            }
        }

        @Override
        protected void onPostExecute(String result) {
            activationRunning = false;
            setLoading(btnActivate, pbActivate, false);

            if ("ok".equals(result) && !token.isEmpty()) {
                SessionManager.save(CodeEntryActivity.this, token, expiresAt);
                startActivity(new Intent(CodeEntryActivity.this, CheckersActivity.class));
                finish();
            } else if ("http_error".equals(result)) {
                if (httpStatus == 400 && errorMessage.contains("invalid_code")) {
                    Toast.makeText(CodeEntryActivity.this, "Код неверен или истёк", Toast.LENGTH_SHORT).show();
                } else if (httpStatus == 400 && errorMessage.contains("code_expired")) {
                    Toast.makeText(CodeEntryActivity.this, "Код истёк. Получите новый код", Toast.LENGTH_SHORT).show();
                } else if (httpStatus == 400 && errorMessage.contains("code_used")) {
                    Toast.makeText(CodeEntryActivity.this, "Код уже использован на другом устройстве", Toast.LENGTH_SHORT).show();
                } else if (httpStatus == 400 && errorMessage.contains("invalid_device")) {
                    Toast.makeText(CodeEntryActivity.this, "Ошибка устройства. Перезапустите приложение", Toast.LENGTH_SHORT).show();
                } else if (httpStatus == 401 || httpStatus == 403) {
                    Toast.makeText(CodeEntryActivity.this, "Доступ запрещён (неверный ключ приложения)", Toast.LENGTH_SHORT).show();
                } else if (httpStatus == 429) {
                    Toast.makeText(CodeEntryActivity.this, "Слишком много попыток. Подождите минуту", Toast.LENGTH_SHORT).show();
                } else if (httpStatus >= 500 && httpStatus < 600) {
                    Toast.makeText(CodeEntryActivity.this, "Серверная ошибка. Попробуйте позже", Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(CodeEntryActivity.this, "Ошибка проверки (" + httpStatus + ")", Toast.LENGTH_SHORT).show();
                }
            } else {
                if ("SocketTimeoutException".equals(errorMessage)) {
                    Toast.makeText(CodeEntryActivity.this, "Таймаут сети. Проверьте интернет", Toast.LENGTH_SHORT).show();
                } else if ("UnknownHostException".equals(errorMessage)) {
                    Toast.makeText(CodeEntryActivity.this, "Нет сети или сервер недоступен", Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(CodeEntryActivity.this, "Ошибка сети", Toast.LENGTH_SHORT).show();
                }
            }
        }
    }

    private void setLoading(MaterialButton button, ProgressBar progress, boolean loading) {
        if (loading) {
            button.setEnabled(false);
            button.setText("Проверка...");
            progress.setVisibility(ProgressBar.VISIBLE);
        } else {
            button.setEnabled(true);
            button.setText("Активировать");
            progress.setVisibility(ProgressBar.GONE);
        }
    }
}
