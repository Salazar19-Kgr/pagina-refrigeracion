const COOKIE_NAME = "rb_admin_session";
const SESSION_MAX_AGE = 60 * 60 * 8; // 8 horas

async function hmac(secret, text) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(text)
  );

  return [...new Uint8Array(signature)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function crearSesion(secret) {
  const timestamp = Math.floor(Date.now() / 1000);
  const firma = await hmac(secret, String(timestamp));

  return `${timestamp}.${firma}`;
}

async function sesionValida(cookie, secret) {
  if (!cookie) return false;

  const partes = cookie.split(".");
  if (partes.length !== 2) return false;

  const timestamp = Number(partes[0]);
  const firma = partes[1];

  if (!Number.isFinite(timestamp)) return false;

  const ahora = Math.floor(Date.now() / 1000);

  if (ahora - timestamp < 0 || ahora - timestamp > SESSION_MAX_AGE) {
    return false;
  }

  const firmaEsperada = await hmac(secret, String(timestamp));

  return firma === firmaEsperada;
}

function obtenerCookie(request, nombre) {
  const cookies = request.headers.get("Cookie") || "";

  for (const parte of cookies.split(";")) {
    const [clave, ...resto] = parte.trim().split("=");

    if (clave === nombre) {
      return resto.join("=");
    }
  }

  return null;
}

function respuestaJson(datos, status = 200) {
  return new Response(JSON.stringify(datos), {
    status,
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
      "Cache-Control": "no-store"
    }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // LOGIN DE ADMINISTRACIÓN
    if (url.pathname === "/api/admin/login" && request.method === "POST") {
      try {
        const datos = await request.json();

        const usuario = String(datos.usuario || "");
        const contraseña = String(datos.contraseña || "");

        if (
          usuario !== env.ADMIN_USER ||
          contraseña !== env.ADMIN_PASS
        ) {
          return respuestaJson(
            { ok: false, mensaje: "Credenciales incorrectas" },
            401
          );
        }

        const sesion = await crearSesion(env.ADMIN_SESSION_SECRET);

        return new Response(
          JSON.stringify({
            ok: true,
            mensaje: "Acceso autorizado"
          }),
          {
            status: 200,
            headers: {
              "Content-Type": "application/json; charset=UTF-8",
              "Cache-Control": "no-store",
              "Set-Cookie":
                `${COOKIE_NAME}=${sesion}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_MAX_AGE}`
            }
          }
        );
      } catch {
        return respuestaJson(
          { ok: false, mensaje: "Solicitud inválida" },
          400
        );
      }
    }

    // CERRAR SESIÓN DE ADMINISTRACIÓN
    if (url.pathname === "/api/admin/logout") {
      return new Response(null, {
        status: 302,
        headers: {
          "Location": "/",
          "Set-Cookie":
            `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
        }
      });
    }

    // /admin.html muestra el formulario de acceso.
    // Las operaciones administrativas estarán protegidas por sesión.

    // PROTECCIÓN DEL PANEL ADMINISTRATIVO
    if (url.pathname === "/admin-panel.html") {
      const cookie = obtenerCookie(request, COOKIE_NAME);

      if (!await sesionValida(cookie, env.ADMIN_SESSION_SECRET)) {
        return Response.redirect(new URL("/", request.url), 302);
      }
    }

    // Todo lo demás continúa funcionando como los Assets actuales.
    return env.ASSETS.fetch(request);
  }
};
