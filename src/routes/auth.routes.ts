import express from 'express';
import * as usuarios from '../services/usuarios.service';
import { crearSesion, destruirSesion, obtenerSesion, limpiarCookieSesion } from '../middleware/sesion';
import rateLimit from 'express-rate-limit';


const router = express.Router();

/**
 * Inicio de sesión.
 *
 * FALLAS:
 *  - Inyección SQL en la verificación de credenciales (ver usuarios.service).
 *  - Contraseñas almacenadas en texto plano.
 *  - Mensajes de error que distinguen "usuario inexistente" de "contraseña
 *    incorrecta" → enumeración de usuarios.
 *  - Sin rate limiting ni bloqueo: fuerza bruta ilimitada.
 *  - El identificador de sesión no se regenera (fijación de sesión).
 */

// Limita los intentos de inicio de sesión para prevenir ataques de fuerza bruta.
const limiterLogin = rateLimit({
  windowMs: 15 * 60 * 1000, // Ventana de 15 minutos.
  limit: 5, // Máximo 5 intentos.
  standardHeaders: true, //informa el límite mediante encabezados HTTP
  legacyHeaders: false, //desactiva los encabezados antiguos
  skipSuccessfulRequests: true, //no cuenta los intentos exitosos
  message: { 
    error: 'Demasiados intentos. Intente nuevamente en 15 minutos.',
  },
});


router.post('/login', limiterLogin, async (req, res, next) => {
  try {
    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({ error: 'Falta usuario o contraseña.' });
    }

    // La verificación de credenciales es la consulta concatenada (SQLi).
    const usuario = await usuarios.autenticar(username, password);

    if (!usuario) { //se utiliza un mensaje generico para evitar revelar si el usuario existe o no, evitando asi la enumeracion de usuarios
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
    }

    crearSesion(req, res, {
      id: usuario.id,
      username: usuario.username,
      rol: usuario.rol,
      nombre: usuario.nombre,
    });

    res.json({
      mensaje: `¡Bienvenido, ${usuario.nombre}!`,
      usuario: {
        id: usuario.id,
        username: usuario.username,
        rol: usuario.rol,
        nombre: usuario.nombre,
      },
    });
  } catch (err) {
    next(err);
  }
});


 /* Devuelve el usuario de la sesión actual.
 */
router.get('/yo', (req, res) => {
  const sesion = obtenerSesion(req);

  // Si no existe una sesión válida, rechaza el acceso.
  if (!sesion) {
    return res.status(401).json({
      error: 'No hay una sesión activa.',
    });
  }

  // Devuelve los datos del usuario autenticado.
  return res.json({
    usuario: sesion.usuario,
  });
});



router.post('/logout', (req, res) => {
  // Elimina la sesión almacenada en el servidor.
  destruirSesion(req);

  // Elimina la cookie del navegador.
  limpiarCookieSesion(res);

  res.json({ mensaje: 'Sesión cerrada.' });
});

export default router;
