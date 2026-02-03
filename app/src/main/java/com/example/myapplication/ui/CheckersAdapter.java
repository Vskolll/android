package com.example.myapplication.ui;

import android.transition.AutoTransition;
import android.transition.TransitionManager;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.util.List;

import com.example.myapplication.R;
import com.example.myapplication.checker.CheckerStatus;

public class CheckersAdapter extends RecyclerView.Adapter<CheckersAdapter.VH> {

    private final List<CheckerItem> items;

    public CheckersAdapter(List<CheckerItem> items) {
        this.items = items;
    }

    public List<CheckerItem> getItems() {
        return items;
    }

    @NonNull
    @Override
    public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_checker, parent, false);
        return new VH(v);
    }

    @Override
    public void onBindViewHolder(@NonNull VH h, int position) {
        CheckerItem it = items.get(position);

        h.tvTitle.setText(it.title);
        h.tvReason.setText("Причина: " + it.reason);
        h.tvDescription.setText(it.description);

        bindStatus(h.tvStatus, it.status);

        h.detailsContainer.setVisibility(it.expanded ? View.VISIBLE : View.GONE);
        h.tvArrow.setText(it.expanded ? "˄" : "˅");

        h.card.setOnClickListener(v -> {
            it.expanded = !it.expanded;
            TransitionManager.beginDelayedTransition(h.card, new AutoTransition());
            notifyItemChanged(h.getBindingAdapterPosition());
        });
    }

    private void bindStatus(TextView tv, CheckerStatus st) {
        if (st == CheckerStatus.PASS) {
            tv.setText("PASS");
            tv.setBackgroundResource(R.drawable.bg_status_pass);
        } else if (st == CheckerStatus.FAIL) {
            tv.setText("FAIL");
            tv.setBackgroundResource(R.drawable.bg_status_fail);
        } else {
            tv.setText("UNKNOWN");
            tv.setBackgroundResource(R.drawable.bg_status_unknown);
        }
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    static class VH extends RecyclerView.ViewHolder {
        final ViewGroup card;
        final TextView tvTitle, tvStatus, tvArrow, tvReason, tvDescription;
        final LinearLayout detailsContainer;

        VH(@NonNull View itemView) {
            super(itemView);
            card = (ViewGroup) itemView.findViewById(R.id.card);
            tvTitle = itemView.findViewById(R.id.tvTitle);
            tvStatus = itemView.findViewById(R.id.tvStatus);
            tvArrow = itemView.findViewById(R.id.tvArrow);
            detailsContainer = itemView.findViewById(R.id.detailsContainer);
            tvReason = itemView.findViewById(R.id.tvReason);
            tvDescription = itemView.findViewById(R.id.tvDescription);
        }
    }
}
