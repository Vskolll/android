package com.example.myapplication.ui;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.os.Bundle;
import android.widget.TextView;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import com.example.myapplication.R;
import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;

public class CheckerDetailActivity extends AppCompatActivity {

    public static final String EXTRA_TITLE = "title";
    public static final String EXTRA_REASON = "reason";
    public static final String EXTRA_DESC = "desc";
    public static final String EXTRA_STATUS = "status";

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_checker_detail);

        MaterialToolbar tb = findViewById(R.id.toolbar);
        tb.setNavigationOnClickListener(v -> finish());

        String title = getIntent().getStringExtra(EXTRA_TITLE);
        String reason = getIntent().getStringExtra(EXTRA_REASON);
        String desc = getIntent().getStringExtra(EXTRA_DESC);

        TextView tvTitle = findViewById(R.id.tvTitle);
        TextView tvReason = findViewById(R.id.tvReason);
        TextView tvBody = findViewById(R.id.tvBody);
        com.google.android.material.card.MaterialCardView banner = findViewById(R.id.bannerCard);
        TextView bannerTitle = findViewById(R.id.bannerTitle);
        TextView bannerSubtitle = findViewById(R.id.bannerSubtitle);

        tvTitle.setText(title == null ? "" : title);
        tvReason.setText(getString(R.string.reason_prefix, (reason == null ? "" : reason)));
        tvBody.setText(desc == null ? "" : desc);

        boolean aospBanner = reason != null && reason.contains("AOSP software attestation root certificate");
        if (aospBanner) {
            banner.setVisibility(android.view.View.VISIBLE);
            bannerTitle.setText(R.string.banner_cert_aosp_title);
            bannerSubtitle.setText(R.string.banner_cert_aosp_subtitle);
        } else {
            banner.setVisibility(android.view.View.GONE);
        }

        MaterialButton btnCopy = findViewById(R.id.btnCopy);
        btnCopy.setOnClickListener(v -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            String text = (title == null ? "" : title)
                    + "\n\n"
                    + getString(R.string.reason_prefix, (reason == null ? "" : reason))
                    + "\n\n"
                    + (desc == null ? "" : desc);
            if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("checker", text));
        });
    }
}
