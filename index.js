// ═══════════════════════════════════════════════════════
//  KYSTE TICKETS v3 — Cloudflare Worker
//  Rôle : OAuth2 Discord + proxy vers API Render
//
//  Secrets CF  : DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET,
//                DISCORD_BOT_TOKEN, SESSION_SECRET
//  Vars CF     : DISCORD_GUILD_ID, DASHBOARD_URL, API_URL
//
//  KV Binding  : KYSTE_KV  (uniquement pour les sessions, très léger)
// ═══════════════════════════════════════════════════════

const CORS = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

const j = (d, s=200) => new Response(JSON.stringify(d), { status:s, headers:{"Content-Type":"application/json",...CORS} });

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { status:204, headers:CORS });

    const url   = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);

    // ── AUTH ROUTES ────────────────────────────────────

    // GET /auth/login
    if (parts[0]==="auth" && parts[1]==="login") {
      const params = new URLSearchParams({
        client_id:     env.DISCORD_CLIENT_ID,
        redirect_uri:  `${env.DASHBOARD_URL}/auth/callback`,
        response_type: "code",
        scope:         "identify",
      });
      return Response.redirect(`https://discord.com/api/oauth2/authorize?${params}`, 302);
    }

    // GET /auth/callback?code=xxx
    if (parts[0]==="auth" && parts[1]==="callback") {
      const code = url.searchParams.get("code");
      if (!code) return new Response("Missing code", { status:400 });

      // Échange code → access token
      const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id:     env.DISCORD_CLIENT_ID,
          client_secret: env.DISCORD_CLIENT_SECRET,
          grant_type:    "authorization_code",
          code,
          redirect_uri:  `${env.DASHBOARD_URL}/auth/callback`,
        }),
      });
      if (!tokenRes.ok) return new Response("Token exchange failed", { status:400 });
      const { access_token } = await tokenRes.json();

      // Récupère profil Discord
      const userRes = await fetch("https://discord.com/api/v10/users/@me", {
        headers: { Authorization: `Bearer ${access_token}` }
      });
      if (!userRes.ok) return new Response("Failed to fetch user", { status:400 });
      const user = await userRes.json();

      // Vérifie si le bot est dans le serveur
      const guildRes = await fetch(`https://discord.com/api/v10/guilds/${env.DISCORD_GUILD_ID}`, {
        headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` }
      });
      const botInGuild = guildRes.ok;

      // Crée session en KV (24h) — juste les infos user, pas les données du bot
      const token = crypto.randomUUID();
      await env.KYSTE_KV.put(`session:${token}`, JSON.stringify({
        user_id:      user.id,
        username:     user.username,
        avatar:       user.avatar
          ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`
          : `https://cdn.discordapp.com/embed/avatars/0.png`,
        bot_in_guild: botInGuild,
        expires:      Date.now() + 86400000,
      }), { expirationTtl: 86400 });

      return Response.redirect(`${env.DASHBOARD_URL}/?session=${token}`, 302);
    }

    // GET /auth/me?session=xxx
    if (parts[0]==="auth" && parts[1]==="me") {
      const token = url.searchParams.get("session");
      if (!token) return j({ error: "No session" }, 401);
      const raw = await env.KYSTE_KV.get(`session:${token}`);
      if (!raw) return j({ error: "Session invalide ou expirée" }, 401);
      const session = JSON.parse(raw);
      if (session.expires < Date.now()) {
        await env.KYSTE_KV.delete(`session:${token}`);
        return j({ error: "Session expirée" }, 401);
      }
      return j(session);
    }

    // GET /auth/logout?session=xxx
    if (parts[0]==="auth" && parts[1]==="logout") {
      const token = url.searchParams.get("session");
      if (token) await env.KYSTE_KV.delete(`session:${token}`);
      return j({ ok: true });
    }

    // ── PROXY VERS RENDER (données du bot) ─────────────
    // Toutes les routes /api/* sont proxifiées vers l'API Render
    if (parts[0]==="api") {
      const target = `${env.API_URL}${url.pathname}${url.search}`;
      const proxied = await fetch(target, {
        method:  request.method,
        headers: { "Content-Type": "application/json" },
        body:    request.method !== "GET" ? request.body : undefined,
      });
      const data = await proxied.text();
      return new Response(data, {
        status:  proxied.status,
        headers: { "Content-Type": "application/json", ...CORS },
      });
    }

    return j({ error: "Not found" }, 404);
  }
};
