package com.example.myapplication.ui;

import android.content.Context;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.core.view.ViewCompat;
import androidx.core.graphics.ColorUtils;
import androidx.recyclerview.widget.RecyclerView;

import com.example.myapplication.R;
import com.example.myapplication.checker.CheckerStatus;
import com.google.android.material.card.MaterialCardView;

import android.graphics.drawable.GradientDrawable;

import java.util.ArrayList;
import java.util.List;

public class CheckersAdapter extends RecyclerView.Adapter<CheckersAdapter.VH> {

    private final List<CheckerUiItem> items = new ArrayList<>();

    public void submit(List<CheckerUiItem> list) {
        items.clear();
        if (list != null) items.addAll(list);
        notifyDataSetChanged();
    }

    public void updateById(String id, CheckerUiItem newItem) {
        if (id == null) return;
        for (int i = 0; i < items.size(); i++) {
            if (id.equals(items.get(i).id)) {
                items.set(i, newItem);
                notifyItemChanged(i);
                return;
            }
        }
    }

    @NonNull
    @Override
    public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_checker, parent, false);
        return new VH(v);
    }

    @Override
    public void onBindViewHolder(@NonNull VH h, int position) {
        CheckerUiItem it = items.get(position);
        Context ctx = h.itemView.getContext();

        h.tvTitle.setText(it.title);
        h.tvSubtitle.setText((it.reason == null || it.reason.trim().isEmpty())
                ? ctx.getString(R.string.checker_reason_empty)
                : it.reason);

        // style by status
        StatusStyle s = StatusStyle.from(ctx, it.status);
        int rowBg = it.critical ? ColorUtils.blendARGB(s.bgColor, 0xFFFFF0F0, 0.35f) : s.bgColor;
        h.card.setCardBackgroundColor(rowBg);
        h.ivStatus.setImageResource(s.iconRes);
        h.ivStatus.setImageTintList(ColorStateList.valueOf(s.fgColor));
        h.viewSeverity.setBackgroundTintList(ColorStateList.valueOf(s.fgColor));

        h.tvBadge.setText(s.badgeText);
        h.tvBadge.setTextColor(s.fgColor);
        int badgeBg = ColorUtils.setAlphaComponent(s.bgColor, 255);
        ViewCompat.setBackgroundTintList(h.tvBadge, ColorStateList.valueOf(badgeBg)); // заливка статуса
        try {
            if (h.tvBadge.getBackground() instanceof GradientDrawable) {
                GradientDrawable d = (GradientDrawable) h.tvBadge.getBackground().mutate();
                d.setStroke(1, s.fgColor);
                d.setColor(badgeBg);
            }
        } catch (Throwable ignored) {}
        // чтобы бейдж выглядел как "плашка", можно сделать его чуть прозрачным: (сверху)

        h.btnDetails.setOnClickListener(v -> {
            Intent intent = new Intent(ctx, CheckerDetailActivity.class);
            intent.putExtra(CheckerDetailActivity.EXTRA_TITLE, it.title);
            intent.putExtra(CheckerDetailActivity.EXTRA_REASON, it.reason);
            intent.putExtra(CheckerDetailActivity.EXTRA_DESC, it.description);
            intent.putExtra(CheckerDetailActivity.EXTRA_STATUS, it.status.name());
            ctx.startActivity(intent);
        });

        // кликом по карточке тоже открываем детали (как в Key Attestation)
        h.card.setOnClickListener(v -> h.btnDetails.performClick());
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    static class VH extends RecyclerView.ViewHolder {
        final MaterialCardView card;
        final ImageView ivStatus;
        final TextView tvTitle;
        final TextView tvSubtitle;
        final TextView tvBadge;
        final View viewSeverity;
        final View btnDetails;

        VH(@NonNull View itemView) {
            super(itemView);
            card = itemView.findViewById(R.id.card);
            ivStatus = itemView.findViewById(R.id.ivStatus);
            tvTitle = itemView.findViewById(R.id.tvTitle);
            tvSubtitle = itemView.findViewById(R.id.tvSubtitle);
            tvBadge = itemView.findViewById(R.id.tvBadge);
            viewSeverity = itemView.findViewById(R.id.viewSeverity);
            btnDetails = itemView.findViewById(R.id.btnDetails);
        }
    }

    static class StatusStyle {
        final int bgColor;
        final int fgColor;
        final int iconRes;
        final String badgeText;

        StatusStyle(int bgColor, int fgColor, int iconRes, String badgeText) {
            this.bgColor = bgColor;
            this.fgColor = fgColor;
            this.iconRes = iconRes;
            this.badgeText = badgeText;
        }

        static StatusStyle from(Context ctx, CheckerStatus st) {
            if (st == null) st = CheckerStatus.UNKNOWN;

            switch (st) {
                case PASS:
                    return new StatusStyle(
                            ctx.getColor(R.color.status_pass_bg),
                            ctx.getColor(R.color.status_pass_fg),
                            R.drawable.ic_status_pass,
                            ctx.getString(R.string.status_pass)
                    );
                case FAIL:
                    return new StatusStyle(
                            ctx.getColor(R.color.status_fail_bg),
                            ctx.getColor(R.color.status_fail_fg),
                            R.drawable.ic_status_fail,
                            ctx.getString(R.string.status_fail)
                    );
                case WARN:
                    return new StatusStyle(
                            ctx.getColor(R.color.status_warn_bg),
                            ctx.getColor(R.color.status_warn_fg),
                            R.drawable.ic_status_warn,
                            ctx.getString(R.string.status_warn)
                    );
                default:
                    return new StatusStyle(
                            ctx.getColor(R.color.status_unknown_bg),
                            ctx.getColor(R.color.status_unknown_fg),
                            R.drawable.ic_status_warn,
                            ctx.getString(R.string.status_unknown)
                    );
            }
        }
    }
}
