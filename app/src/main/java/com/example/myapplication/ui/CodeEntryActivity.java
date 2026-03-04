package com.example.myapplication.ui;

import android.annotation.SuppressLint;
import android.content.Intent;
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

public class CodeEntryActivity extends AppCompatActivity {

    private static final String BASE_URL = "https://v7ck9ll-server.onrender.com";
    private static final String APP_SECRET = "wefqfqf1f134gref1dw";

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_code_entry);

        EditText etCode = findViewById(R.id.etCode);
        MaterialButton btnActivate = findViewById(R.id.btnActivate);
        ProgressBar pbActivate = findViewById(R.id.pbActivate);

        btnActivate.setOnClickListener(v -> {
            String code = etCode.getText() == null ? "" : etCode.getText().toString().trim();
            if (code.isEmpty()) {
                Toast.makeText(this, "Введите код", Toast.LENGTH_SHORT).show();
                return;
            }
            setLoading(btnActivate, pbActivate, true);
            new VerifyTask(code, getDeviceIdSafe()).execute();
        });
    }

    @SuppressLint("HardwareIds")
    private String getDeviceIdSafe() {
        return Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);
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
            try {
                URL url = new URL(BASE_URL + "/verify");
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
            MaterialButton btnActivate = findViewById(R.id.btnActivate);
            ProgressBar pbActivate = findViewById(R.id.pbActivate);
            setLoading(btnActivate, pbActivate, false);

            if ("ok".equals(result) && !token.isEmpty()) {
                SessionManager.save(CodeEntryActivity.this, token, expiresAt);
                startActivity(new Intent(CodeEntryActivity.this, CheckersActivity.class));
                finish();
            } else if ("http_error".equals(result)) {
                if (httpStatus == 401) {
                    Toast.makeText(CodeEntryActivity.this, "Код неверен или истёк", Toast.LENGTH_SHORT).show();
                } else if (httpStatus == 403) {
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
