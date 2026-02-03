package com.example.myapplication.ui;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.floatingactionbutton.FloatingActionButton;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.example.myapplication.R;
import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.CheckerStatus;

public class CheckersActivity extends AppCompatActivity {

    private CheckersAdapter adapter;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    private FloatingActionButton fab;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_checkers);

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        toolbar.setTitle("Checkers");

        RecyclerView rv = findViewById(R.id.rvCheckers);
        fab = findViewById(R.id.fabRun);

        rv.setLayoutManager(new LinearLayoutManager(this));

        // Пока вручную, чтобы UI всегда был
        List<CheckerItem> items = new ArrayList<>();
        items.add(new CheckerItem("bootloader_vb", "Bootloader / Verified Boot"));
        items.add(new CheckerItem("emulator", "Emulator detection"));
        items.add(new CheckerItem("debuggable", "App debuggable flag"));
        items.add(new CheckerItem("root", "Root detected"));
        items.add(new CheckerItem("fw_keys", "Firmware keys / certificate"));
        items.add(new CheckerItem("runtime_tamper", "Runtime trigger / tamper"));
        items.add(new CheckerItem("magisk", "Magisk artifacts"));

        adapter = new CheckersAdapter(items);
        rv.setAdapter(adapter);

        fab.setOnClickListener(v -> runAllChecksStub());
    }

    /**
     * Заглушечный прогон в фоне, чтобы не лагал UI.
     * Позже вместо stub-логики подключим реальные IChecker и registry.
     */
    private void runAllChecksStub() {
        fab.setEnabled(false);

        executor.execute(() -> {
            // ТУТ имитация "тяжелых" проверок
            for (CheckerItem it : adapter.getItems()) {
                // Типа делаем работу
                sleepSilently(120);

                // Заглушка-результат (можешь поменять как хочешь)
                CheckerResult r = CheckerResult.unknown(
                        "Stub",
                        "Проверка ещё не подключена. ID=" + it.id
                );

                // Применяем результат прямо в фоне (это просто поля объекта)
                it.applyResult(r);

                // Можно также менять статус “для теста”
                // it.status = CheckerStatus.PASS;
                // it.reason = "OK";
                // it.description = "Test PASS";
            }

            // Обновление UI одним заходом
            mainHandler.post(() -> {
                adapter.notifyDataSetChanged();
                fab.setEnabled(true);
            });
        });
    }

    private void sleepSilently(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException ignored) {}
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdownNow();
    }
}
