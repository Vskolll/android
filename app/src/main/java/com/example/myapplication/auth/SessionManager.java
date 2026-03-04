package com.example.myapplication.auth;

import android.content.Context;
import android.content.SharedPreferences;

public class SessionManager {

    private static final String PREF = "v7_session";
    private static final String KEY_TOKEN = "token";
    private static final String KEY_EXPIRES = "expires_at";

    public static void save(Context ctx, String token, long expiresAt) {
        SharedPreferences sp = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE);
        sp.edit().putString(KEY_TOKEN, token).putLong(KEY_EXPIRES, expiresAt).apply();
    }

    public static void clear(Context ctx) {
        SharedPreferences sp = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE);
        sp.edit().clear().apply();
    }

    public static boolean isValid(Context ctx) {
        SharedPreferences sp = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE);
        long exp = sp.getLong(KEY_EXPIRES, 0L);
        return exp > (System.currentTimeMillis() / 1000L);
    }

    public static String token(Context ctx) {
        SharedPreferences sp = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE);
        return sp.getString(KEY_TOKEN, "");
    }
}
