package com.example.myapplication.ui;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.content.Intent;
import android.net.Uri;

import androidx.annotation.Nullable;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.example.myapplication.R;
import com.example.myapplication.checker.CheckerRegistry;
import com.example.myapplication.checker.CheckerResult;
import com.example.myapplication.checker.CheckerStatus;
import com.example.myapplication.checker.IChecker;
import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.chip.Chip;
import com.google.android.material.chip.ChipGroup;
import com.google.android.material.card.MaterialCardView;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class CheckersActivity extends AppCompatActivity {

    private CheckersAdapter adapter;
    private final ExecutorService exec = Executors.newFixedThreadPool(2);
    private final Handler main = new Handler(Looper.getMainLooper());
    private final List<CheckerUiItem> allItems = new ArrayList<>();
    private Filter currentFilter = Filter.ALL;
    private SummaryViews summaryViews;
    private static final String AOSP_BANNER_KEY = "AOSP software attestation root certificate";
    private static final String UNLOCK_KEY = "Bootloader: UNLOCKED";
    private static final String VB_RED_KEY = "Verified Boot: RED";
    private static final String VB_ORANGE_KEY = "Verified Boot: ORANGE";
    private static final String BOOTLOADER_ID = "bootloader_vb";
    private int scrollOffsetY = 0;
    private static final String PUBG_PACKAGE = "com.tencent.ig";
    private static final String PUBG_MARKET_URL = "market://details?id=" + PUBG_PACKAGE;
    private static final String PUBG_WEB_URL = "https://play.google.com/store/apps/details?id=" + PUBG_PACKAGE;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (!com.example.myapplication.auth.SessionManager.isValid(this)) {
            startActivity(new Intent(this, CodeEntryActivity.class));
            finish();
            return;
        }
        setContentView(R.layout.activity_checkers);

        MaterialToolbar tb = findViewById(R.id.toolbar);
        setSupportActionBar(tb);

        summaryViews = new SummaryViews(findViewById(R.id.summaryCard));
        summaryViews.bindAospBanner(findViewById(R.id.bannerAospCard));
        summaryViews.bindUnlockBanner(findViewById(R.id.bannerUnlockCard));
        summaryViews.bindVbBanner(findViewById(R.id.bannerVbCard));

        findViewById(R.id.btnOpenPubgBottom).setOnClickListener(v -> openPubgStore());
        RecyclerView rv = findViewById(R.id.rvCheckers);
        rv.setLayoutManager(new LinearLayoutManager(this));
        adapter = new CheckersAdapter();
        rv.setAdapter(adapter);
        rv.addOnScrollListener(new RecyclerView.OnScrollListener() {
            @Override
            public void onScrolled(@NonNull RecyclerView recyclerView, int dx, int dy) {
                scrollOffsetY += dy;
            }
        });

        setupFilterChips();
        runAll();
    }

    private void openPubgStore() {
        try {
            Intent market = new Intent(Intent.ACTION_VIEW, Uri.parse(PUBG_MARKET_URL));
            market.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(market);
        } catch (Throwable t) {
            android.widget.Toast.makeText(this,
                    "Play Market недоступен", android.widget.Toast.LENGTH_SHORT).show();
        }
    }

    private void setupFilterChips() {
        ChipGroup group = findViewById(R.id.chipFilter);
        Chip chipAll = findViewById(R.id.chipAll);
        chipAll.setChecked(true);
        group.setOnCheckedChangeListener((g, checkedId) -> {
            currentFilter = filterFromId(checkedId);
            applyFilterAndSort();
        });
    }

    private void runAll() {
        final List<IChecker> checkers = CheckerRegistry.all();

        // первичная загрузка "как будто всё есть"
        allItems.clear();
        for (IChecker c : checkers) {
            allItems.add(new CheckerUiItem(c.id(), c.title(),
                    CheckerResult.unknown(
                            getString(R.string.checker_running_title),
                            getString(R.string.checker_running_desc)
                    )));
        }
        applyFilterAndSort();

        for (IChecker c : checkers) {
            exec.execute(() -> {
                CheckerResult r;
                try {
                    r = c.run(getApplicationContext());
                } catch (Throwable t) {
                    r = CheckerResult.unknown("Exception", String.valueOf(t));
                }

                CheckerUiItem item = new CheckerUiItem(c.id(), c.title(), r);
                main.post(() -> {
                    updateItemById(c.id(), item);
                    applyFilterAndSort();
                });
            });
        }
    }

    private void updateItemById(String id, CheckerUiItem newItem) {
        if (id == null) return;
        for (int i = 0; i < allItems.size(); i++) {
            if (id.equals(allItems.get(i).id)) {
                allItems.set(i, newItem);
                return;
            }
        }
        allItems.add(newItem);
    }

    private void applyFilterAndSort() {
        List<CheckerUiItem> filtered = new ArrayList<>();
        for (CheckerUiItem it : allItems) {
            if (it != null && it.status == CheckerStatus.UNKNOWN) continue;
            if (currentFilter.matches(it.status)) filtered.add(it);
        }
        Collections.sort(filtered, new StatusComparator());
        adapter.submit(filtered);
        if (summaryViews != null) summaryViews.update(allItems);
    }

    private Filter filterFromId(int id) {
        if (id == R.id.chipFail) return Filter.FAIL;
        if (id == R.id.chipWarn) return Filter.WARN;
        if (id == R.id.chipPass) return Filter.PASS;
        return Filter.ALL;
    }

    @Override
    protected void onDestroy() {
        exec.shutdownNow();
        main.removeCallbacksAndMessages(null);
        super.onDestroy();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (!com.example.myapplication.auth.SessionManager.isValid(this)) {
            startActivity(new Intent(this, CodeEntryActivity.class));
            finish();
        }
    }

    private enum Filter {
        ALL, FAIL, WARN, PASS;

        boolean matches(CheckerStatus status) {
            if (this == ALL) return true;
            if (status == null) return false;
            switch (this) {
                case FAIL: return status == CheckerStatus.FAIL;
                case WARN: return status == CheckerStatus.WARN;
                case PASS: return status == CheckerStatus.PASS;
                default: return true;
            }
        }
    }

    private static final class StatusComparator implements Comparator<CheckerUiItem> {
        @Override
        public int compare(CheckerUiItem a, CheckerUiItem b) {
            int sa = order(a == null ? null : a.status);
            int sb = order(b == null ? null : b.status);
            if (sa != sb) return sa - sb;
            String ta = a == null ? "" : a.title;
            String tb = b == null ? "" : b.title;
            return ta.compareToIgnoreCase(tb);
        }

        private int order(CheckerStatus s) {
            if (s == CheckerStatus.FAIL) return 0;
            if (s == CheckerStatus.WARN) return 1;
            if (s == CheckerStatus.PASS) return 2;
            return 3;
        }
    }

    private static final class SummaryViews {
        final MaterialCardView card;
        final android.widget.TextView title;
        final android.widget.TextView value;
        final android.widget.TextView counts;
        MaterialCardView bannerAosp;
        MaterialCardView bannerUnlock;
        MaterialCardView bannerVb;

        SummaryViews(MaterialCardView card) {
            this.card = card;
            this.title = card.findViewById(R.id.tvSummaryTitle);
            this.value = card.findViewById(R.id.tvSummaryValue);
            this.counts = card.findViewById(R.id.tvSummaryCounts);
        }

        void bindAospBanner(MaterialCardView bannerCard) {
            this.bannerAosp = bannerCard;
        }

        void bindUnlockBanner(MaterialCardView bannerCard) {
            this.bannerUnlock = bannerCard;
        }

        void bindVbBanner(MaterialCardView bannerCard) {
            this.bannerVb = bannerCard;
        }

        void update(List<CheckerUiItem> items) {
            int fail = 0, warn = 0, pass = 0, unknown = 0;
            CertFlag certFlag = CertFlag.NONE;
            String certSubject = "";
            String certSha = "";
            boolean unlockFlag = false;
            boolean vbFlag = false;
            for (CheckerUiItem it : items) {
                CheckerStatus st = it == null ? null : it.status;
                if (st == CheckerStatus.FAIL) fail++;
                else if (st == CheckerStatus.WARN) warn++;
                else if (st == CheckerStatus.PASS) pass++;
                else unknown++;
                if (it != null && BOOTLOADER_ID.equals(it.id)) {
                    CertFlag cf = detectCertFlag(it.description);
                    if (cf != CertFlag.NONE) {
                        certFlag = cf;
                        certSubject = extractLineValue(it.description, "rootSubject = ");
                        certSha = extractLineValue(it.description, "rootSHA256 = ");
                    }
                }
                if (!unlockFlag && it != null && it.reason != null && it.reason.contains(UNLOCK_KEY)) {
                    unlockFlag = true;
                }
                if (!vbFlag && it != null && it.reason != null &&
                        (it.reason.contains(VB_RED_KEY) || it.reason.contains(VB_ORANGE_KEY))) {
                    vbFlag = true;
                }
            }

            counts.setText(card.getResources().getString(
                    R.string.summary_counts, fail, warn, pass, unknown));

            if (fail > 0) {
                value.setText(R.string.summary_risk);
                value.setTextColor(card.getResources().getColor(R.color.summary_risk));
                card.setStrokeColor(card.getResources().getColor(R.color.summary_risk));
            } else if (warn > 0 || unknown > 0) {
                value.setText(R.string.summary_warn);
                value.setTextColor(card.getResources().getColor(R.color.summary_warn));
                card.setStrokeColor(card.getResources().getColor(R.color.summary_warn));
            } else {
                value.setText(R.string.summary_clean);
                value.setTextColor(card.getResources().getColor(R.color.summary_clean));
                card.setStrokeColor(card.getResources().getColor(R.color.summary_clean));
            }

            if (bannerAosp != null) {
                if (certFlag == CertFlag.NONE) {
                    bannerAosp.setVisibility(android.view.View.GONE);
                } else {
                    applyCertBanner(bannerAosp, certFlag, certSubject, certSha);
                    bannerAosp.setVisibility(android.view.View.VISIBLE);
                }
            }
            if (bannerUnlock != null) {
                bannerUnlock.setVisibility(unlockFlag ? android.view.View.VISIBLE : android.view.View.GONE);
            }
            if (bannerVb != null) {
                bannerVb.setVisibility(vbFlag ? android.view.View.VISIBLE : android.view.View.GONE);
            }
        }

        private void applyCertBanner(MaterialCardView banner, CertFlag flag, String subject, String sha) {
            android.widget.TextView title = banner.findViewById(R.id.bannerAospTitle);
            android.widget.TextView subtitle = banner.findViewById(R.id.bannerAospSubtitle);
            if (flag == CertFlag.AOSP) {
                title.setText(R.string.banner_cert_aosp_title);
                subtitle.setText(R.string.banner_cert_aosp_subtitle);
                banner.setCardBackgroundColor(banner.getResources().getColor(R.color.banner_fail_bg));
                banner.setStrokeColor(banner.getResources().getColor(R.color.banner_fail_stroke));
                title.setTextColor(banner.getResources().getColor(R.color.banner_fail_fg));
                subtitle.setTextColor(banner.getResources().getColor(R.color.banner_fail_fg));
            } else if (flag == CertFlag.HARDWARE) {
                title.setText(R.string.banner_cert_hw_title);
                subtitle.setText(R.string.banner_cert_hw_subtitle);
                banner.setCardBackgroundColor(banner.getResources().getColor(R.color.banner_ok_bg));
                banner.setStrokeColor(banner.getResources().getColor(R.color.banner_ok_stroke));
                title.setTextColor(banner.getResources().getColor(R.color.banner_ok_fg));
                subtitle.setTextColor(banner.getResources().getColor(R.color.banner_ok_fg));
            } else {
                title.setText(R.string.banner_cert_sw_title);
                subtitle.setText(R.string.banner_cert_sw_subtitle);
                banner.setCardBackgroundColor(banner.getResources().getColor(R.color.banner_fail_bg));
                banner.setStrokeColor(banner.getResources().getColor(R.color.banner_fail_stroke));
                title.setTextColor(banner.getResources().getColor(R.color.banner_fail_fg));
                subtitle.setTextColor(banner.getResources().getColor(R.color.banner_fail_fg));
            }

            if (subject != null && !subject.isEmpty()) {
                subtitle.setText(subtitle.getText() + "\n" + subject);
            }
            if (sha != null && !sha.isEmpty()) {
                subtitle.setText(subtitle.getText() + "\n" + sha);
            }
        }

        private CertFlag detectCertFlag(String desc) {
            if (desc == null) return CertFlag.NONE;
            String d = desc.toLowerCase();
            if (d.contains(AOSP_BANNER_KEY.toLowerCase())) return CertFlag.AOSP;
            if (d.contains("securitylevel = tee") || d.contains("securitylevel = strongbox")) return CertFlag.HARDWARE;
            if (d.contains("securitylevel = software")) return CertFlag.SOFTWARE;
            return CertFlag.NONE;
        }

        private String extractLineValue(String desc, String prefix) {
            if (desc == null || prefix == null) return "";
            String[] lines = desc.split("\n");
            for (String line : lines) {
                if (line.contains(prefix)) {
                    return line.substring(line.indexOf(prefix) + prefix.length()).trim();
                }
            }
            return "";
        }
    }

    private enum CertFlag {
        NONE, AOSP, HARDWARE, SOFTWARE
    }
}
