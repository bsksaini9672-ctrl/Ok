const encoder = new TextEncoder();

function base64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function textBase64url(text) {
  return btoa(unescape(encodeURIComponent(text)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function signToken(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(payload)
  );

  return base64url(signature);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Test
    if (url.pathname === "/") {
      return new Response("ReplyMate License Server OK");
    }

    // Generate license token
    if (url.pathname === "/admin/generate") {
      const auth = request.headers.get("Authorization");

      if (!env.ADMIN_SECRET || auth !== `Bearer ${env.ADMIN_SECRET}`) {
        return new Response("Unauthorized", { status: 401 });
      }

      const deviceId = url.searchParams.get("device_id");

      if (!deviceId) {
        return new Response("device_id required", { status: 400 });
      }

      const days = Number(url.searchParams.get("days") || "365");

      const expires = Date.now() + days * 24 * 60 * 60 * 1000;

      const data = JSON.stringify({
        device_id: deviceId,
        expires
      });

      const payload = textBase64url(data);
      const signature = await signToken(payload, env.LICENSE_SECRET);

      return new Response(
        JSON.stringify({
          success: true,
          device_id: deviceId,
          expires,
          token: `${payload}.${signature}`
        }),
        {
          headers: {
            "Content-Type": "application/json"
          }
        }
      );
    }

    // Verify license
    if (url.pathname === "/verify") {
      const deviceId = url.searchParams.get("device_id");
      const token = url.searchParams.get("token");

      if (!deviceId || !token) {
        return new Response(
          JSON.stringify({
            authorized: false,
            error: "device_id and token required"
          }),
          {
            status: 400,
            headers: { "Content-Type": "application/json" }
          }
        );
      }

      try {
        const parts = token.split(".");

        if (parts.length !== 2) {
          throw new Error("Invalid token");
        }

        const [payload, signature] = parts;

        const expected = await signToken(payload, env.LICENSE_SECRET);

        if (signature !== expected) {
          throw new Error("Invalid signature");
        }

        const data = JSON.parse(
          decodeURIComponent(
            escape(
              atob(
                payload
                  .replace(/-/g, "+")
                  .replace(/_/g, "/")
                  .padEnd(payload.length + (4 - payload.length % 4) % 4, "=")
              )
            )
          )
        );

        if (data.device_id !== deviceId) {
          throw new Error("Device mismatch");
        }

        if (Date.now() > data.expires) {
          throw new Error("License expired");
        }

        return new Response(
          JSON.stringify({
            authorized: true,
            device_id: deviceId,
            expires: data.expires
          }),
          {
            headers: { "Content-Type": "application/json" }
          }
        );
      } catch (e) {
        return new Response(
          JSON.stringify({
            authorized: false,
            error: "Invalid or expired license"
          }),
          {
            status: 403,
            headers: { "Content-Type": "application/json" }
          }
        );
      }
    }

    return new Response("Not Found", { status: 404 });
  }
};
