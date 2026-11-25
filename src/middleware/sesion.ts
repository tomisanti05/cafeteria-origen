/**
 * Gestión de sesiones.
 *
 * -----------------------------------------------------------------------------
 * FALLA — Gestión de sesiones insegura (Autenticación insegura)
 * -----------------------------------------------------------------------------
 * 1. El identificador de sesión es un contador incremental (`sesion_1`,
 *    `sesion_2`, ...): es PREDECIBLE y adivinable. Un atacante puede recorrer
 *    los valores y usurpar la sesión de otro usuario (fijación de sesión).
 * 2. La cookie se emite SIN `httpOnly` (JavaScript puede leerla), SIN `secure`
 *    (viaja en texto plano por HTTP) y SIN `sameSite` (el navegador la manda
 *    también en peticiones desde otros sitios → facilita CSRF).
 * 3. Las sesiones NO expiran nunca.
 * 4. Al iniciar sesión no se regenera el identificador.
 * 5. El cierre de sesión sólo borra la cookie del cliente: la sesión sigue
 *    viva en el servidor.
 *
 * Corrección: usar crypto.randomUUID() (o crypto.randomBytes -> hex) para el
 * id, con expiración por inactividad y absoluta, cookie con
 * { httpOnly: true, secure: true, sameSite: 'lax' }, regeneración del id tras
 * el login y borrado de la sesión en el servidor al hacer logout.
 * -----------------------------------------------------------------------------
 */

import type { Request, Response } from 'express';

import type { Sesion, UsuarioSesion } from '../tipos';

import { randomUUID } from 'node:crypto';
const DURACION_INACTIVIDAD = 30 * 60 * 1000; // tiempo maximo permitido sin actividdad (30 minutos)
const DURACION_MAXIMA = 8 * 60 * 60 * 1000; // tiempo maximo de una sesion (8 horas)

//configuracion de la seguridad de la cookie
const secureCookie = process.env.NODE_ENV === 'production';

const opcionesCookie = {
  path: '/', ///define que la cookie es válida en toda la aplicación
  httpOnly: true, //impide que js pueda acceder a la cookie
  secure: secureCookie, //exige https en producción
  sameSite: 'lax' as const, //ayuda a prevenir ataques CSRF
};

export const sesiones = new Map<string, Sesion>();
let contadorSesiones = 0;

/** Lee las cookies de la petición (parser mínimo, sin dependencias). */
export function leerCookies(req: Request): Record<string, string> {
  const cookies: Record<string, string> = {};
  const header = req.headers.cookie;
  if (!header) return cookies;
  for (const parte of header.split(';')) {
    const separador = parte.indexOf('=');
    if (separador < 0) continue;
    const nombre = parte.slice(0, separador).trim();
    const valor = parte.slice(separador + 1).trim();
    if (nombre) cookies[nombre] = decodeURIComponent(valor);
  }
  return cookies;
}



/** Crea una sesión nueva para el usuario y setea la cookie. */
export function crearSesion(
  req: Request,
  res: Response,
  usuario: UsuarioSesion
): string {


// Elimina una sesión anterior asociada a la cookie recibida.
const cookies = leerCookies(req);
if (cookies.sid) {
  sesiones.delete(cookies.sid);
}

  // FALLA: identificador predecible.
  const id = randomUUID(); //(corregido) 

  // FALLA: la sesión nunca expira.
  const ahora = Date.now(); //registra el momento de creación de la sesión
  sesiones.set(id, {
    usuario,
    creadaEn: ahora,
    expiraEn: ahora + DURACION_INACTIVIDAD, // (corregido) se establece la expiración por inactividad
  });

  // FALLA: cookie sin httpOnly / secure / sameSite.
  res.cookie('sid', id, opcionesCookie); //configura la cookie con las opciones de seguridad definidas
  return id;
}

/** Devuelve la sesión de la petición, si existe. */
export function obtenerSesion(req: Request): Sesion | null {
  const cookies = leerCookies(req);
  const id = cookies.sid;

  if (!id) return null;

  const sesion = sesiones.get(id);

  if (!sesion) return null;

  const ahora = Date.now();

  // Calcula el vencimiento absoluto de la sesión.
  const vencimientoAbsoluto = sesion.creadaEn + DURACION_MAXIMA;

  // Comprueba si venció por inactividad o por tiempo máximo.
  if (
    sesion.expiraEn === null ||
    ahora >= sesion.expiraEn ||
    ahora >= vencimientoAbsoluto
  ) {
    sesiones.delete(id);
    return null;
  }

  // Renueva el tiempo de inactividad sin superar las 8 horas.
  sesion.expiraEn = Math.min(
    ahora + DURACION_INACTIVIDAD,
    vencimientoAbsoluto
  );

  return sesion;
}

/** Cierra la sesión en el servidor (debería llamarse en el logout). */
export function destruirSesion(req: Request): void {
  const cookies = leerCookies(req);
  const id = cookies.sid;
  if (id) sesiones.delete(id);
}

/** Elimina la cookie de sesión del navegador.*/
export function limpiarCookieSesion(res: Response): void {
  res.clearCookie('sid', opcionesCookie);
}