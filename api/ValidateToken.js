import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

function getSupabase() {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_KEY;
    if (!url || !key) throw new Error("Supabase env vars not set");
    return createClient(url, key);
}

function b64url(input) {
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
    return buf.toString("base64").replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
}

function verifyJWT(token, secret) {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [header, body, sig] = parts;
    const expected = b64url(crypto.createHmac("sha256", secret).update(`${header}.${body}`).digest());
    try { if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null; }
    catch { return null; }
    const payload = JSON.parse(Buffer.from(body.replace(/-/g,"+").replace(/_/g,"/"), "base64").toString("utf8"));
    if (!payload.exp || Math.floor(Date.now() / 1000) > payload.exp) return null;
    return payload;
}

export default async function handler(req, res) {
    if (req.method !== "POST")
        return res.status(405).json({ status: "METHOD_NOT_ALLOWED" });

    try {
        const { token = "" } = req.body || {};
        if (!token) return res.status(400).json({ status: "BAD_REQUEST" });

        const JWT_SECRET = process.env.JWT_SECRET;
        if (!JWT_SECRET) return res.status(500).json({ status: "SERVER_MISCONFIGURED" });

        // ── Step 1: JWT signature + expiry ────────────────────────────────────
        const payload = verifyJWT(token, JWT_SECRET);
        if (!payload) return res.status(401).json({ status: "INVALID_TOKEN" });

        // ── Step 2: Supabase — exists, not revoked, not expired ───────────────
        try {
            const supabase = getSupabase();
            const { data, error } = await supabase
                .from("device_tokens")
                .select("id, revoked, expires_at")
                .eq("id", payload.jti)
                .single();

            if (error || !data)
                return res.status(401).json({ status: "TOKEN_NOT_FOUND" });

            if (data.revoked) {
                console.warn(`[VALIDATE] Revoked jti=${payload.jti} device=${payload.sub}`);
                return res.status(401).json({ status: "TOKEN_REVOKED" });
            }

            if (new Date(data.expires_at) < new Date())
                return res.status(401).json({ status: "TOKEN_EXPIRED" });

        } catch (e) {
            console.warn("[VALIDATE] Supabase down — JWT-only fallback:", e.message);
        }

        // ── Step 3: Device blocklist ──────────────────────────────────────────
        try {
            const supabase = getSupabase();
            const { data: blocked } = await supabase
                .from("blocked_devices")
                .select("device_id")
                .eq("device_id", payload.sub)
                .maybeSingle();
            if (blocked) {
                console.warn(`[VALIDATE] Blocked device=${payload.sub}`);
                return res.status(403).json({ status: "DEVICE_BANNED" });
            }
        } catch (e) { console.warn("[VALIDATE] blocklist check failed:", e.message); }

        console.log(`[VALIDATE] OK jti=${payload.jti} device=${payload.sub}`);
        return res.status(200).json({
            status: "OK", device: payload.sub, vr: payload.vr,
            pkg: payload.pkg, ver: payload.ver, expires: payload.exp,
        });

    } catch (err) {
        console.error("[VALIDATE] Unhandled:", err);
        return res.status(500).json({ status: "SERVER_ERROR" });
    }
}
