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

    // CREAR PRECIO
    if (url.pathname === "/api/admin/precios" && request.method === "POST") {
      try {
        const datos = await request.json();

        const nombre = String(datos.nombre || "").trim();
        const descripcion = String(datos.descripcion || "").trim();
        const precioTexto = String(datos.precio_texto || "").trim();
        const precio = Number(datos.precio || 0);
        const activo = datos.activo === false ? 0 : 1;
        const orden = Number(datos.orden || 0);

        if (!nombre) {
          return respuestaJson(
            { ok: false, mensaje: "El nombre es obligatorio" },
            400
          );
        }

        await env.DB.prepare(`
          INSERT INTO precios
          (nombre, descripcion, precio, precio_texto, activo, orden)
          VALUES (?, ?, ?, ?, ?, ?)
        `)
          .bind(
            nombre,
            descripcion,
            precio,
            precioTexto || null,
            activo,
            orden
          )
          .run();

        return respuestaJson({
          ok: true,
          mensaje: "Precio creado correctamente"
        }, 201);

      } catch (error) {
        return respuestaJson(
          { ok: false, mensaje: "Error al crear precio" },
          500
        );
      }
    }

    // EDITAR PRECIO
    if (url.pathname === "/api/admin/precios" && request.method === "PUT") {
      try {
        const datos = await request.json();

        const id = Number(datos.id);
        const nombre = String(datos.nombre || "").trim();
        const descripcion = String(datos.descripcion || "").trim();
        const precioTexto = String(datos.precio_texto || "").trim();
        const precio = Number(datos.precio || 0);
        const activo = datos.activo === false ? 0 : 1;
        const orden = Number(datos.orden || 0);

        if (!id || !nombre) {
          return respuestaJson(
            { ok: false, mensaje: "ID y nombre son obligatorios" },
            400
          );
        }

        const resultado = await env.DB.prepare(`
          UPDATE precios
          SET nombre = ?,
              descripcion = ?,
              precio = ?,
              precio_texto = ?,
              activo = ?,
              orden = ?,
              actualizado_en = CURRENT_TIMESTAMP
          WHERE id = ?
        `)
          .bind(
            nombre,
            descripcion,
            precio,
            precioTexto || null,
            activo,
            orden,
            id
          )
          .run();

        return respuestaJson({
          ok: true,
          mensaje: resultado.meta.changes
            ? "Precio actualizado correctamente"
            : "No se encontró el precio"
        });

      } catch (error) {
        return respuestaJson(
          { ok: false, mensaje: "Error al actualizar precio" },
          500
        );
      }
    }

    // ELIMINAR PRECIO
    if (url.pathname === "/api/admin/precios" && request.method === "DELETE") {
      try {
        const datos = await request.json();
        const id = Number(datos.id);

        if (!id) {
          return respuestaJson(
            { ok: false, mensaje: "ID inválido" },
            400
          );
        }

        const resultado = await env.DB.prepare(`
          DELETE FROM precios WHERE id = ?
        `)
          .bind(id)
          .run();

        return respuestaJson({
          ok: true,
          mensaje: resultado.meta.changes
            ? "Precio eliminado correctamente"
            : "No se encontró el precio"
        });

      } catch (error) {
        return respuestaJson(
          { ok: false, mensaje: "Error al eliminar precio" },
          500
        );
      }
    }

    // LEER PRECIOS DESDE D1
    if (url.pathname === "/api/admin/precios" && request.method === "GET") {
      try {
        const { results } = await env.DB
          .prepare(`
            SELECT id, nombre, descripcion, precio, precio_texto, activo, orden
            FROM precios
            ORDER BY orden ASC, id ASC
          `)
          .all();

        return respuestaJson({
          ok: true,
          precios: results
        });
      } catch (error) {
        return respuestaJson(
          { ok: false, mensaje: "Error al consultar precios" },
          500
        );
      }
    }

    // LEER SERVICIOS DESDE D1
    if (url.pathname === "/api/admin/servicios" && request.method === "GET") {
      try {
        const { results } = await env.DB
          .prepare(`
            SELECT id, nombre, descripcion, categoria, activo, orden
            FROM servicios
            ORDER BY orden ASC, id ASC
          `)
          .all();

        return respuestaJson({
          ok: true,
          servicios: results
        });
      } catch (error) {
        return respuestaJson(
          { ok: false, mensaje: "Error al consultar servicios" },
          500
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
