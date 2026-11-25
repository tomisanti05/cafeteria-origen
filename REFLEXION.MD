# Reflexion Santiago De Dios 
- **No confiar en código generado sin revisión ("vibe coding"):** Las fallas de inyección SQL, falta de validación y contraseñas en texto plano surgieron por copiar código sin auditarlo. En un proyecto real debe haber revisión de código (*code review*) obligatoria antes de mergear.
- **Consultas parametrizadas y validación por defecto:** Usar siempre consultas parametrizadas (`$1`, `$2`) o un ORM/query builder seguro, y validar tipo, rango y listas blancas en el servidor (nunca confiar en el frontend) para evitar pedidos con montos negativos o filtros manipulables.
- **Almacenamiento seguro de credenciales:** Nunca guardar contraseñas en texto plano; usar algoritmos de hashing lento con *salt* por usuario (`bcrypt` o `argon2`) desde el primer día.
- **Pruebas automatizadas de seguridad en CI/CD:** Integrar análisis estático (`check:security`) y tests de seguridad (`test:seguridad`) en el pipeline de integración continua para detectar regresiones antes de llegar a producción.


# Reflexión Maitena Surop
- **Protección contra ataques de fuerza bruta:** Limitar los intentos de inicio de sesión mediante *rate limiting* para evitar que un atacante pueda probar contraseñas ilimitadamente. También es importante permitir nuevos intentos después del período de bloqueo.
- **Prevención de enumeración de usuarios:** Utilizar mensajes de error genéricos al iniciar sesión, sin indicar si el usuario no existe o si la contraseña es incorrecta. De esta manera se evita revelar información sobre las cuentas registradas.
- **Gestión segura de sesiones:** Utilizar identificadores aleatorios mediante `crypto.randomUUID()` en lugar de identificadores predecibles. Configurar cookies con `HttpOnly`, `Secure` y `SameSite`, además de establecer tiempos de expiración por inactividad y duración máxima.
- **Invalidación y cierre de sesiones:** Eliminar las sesiones anteriores al iniciar sesión y destruir la sesión almacenada en el servidor al cerrar sesión. No alcanza solamente con borrar la cookie del navegador.
- **Validación segura de contraseñas:** Comprendí la importancia de trabajar coordinadamente con el almacenamiento de credenciales mediante `bcrypt`. Mientras se utiliza `bcrypt.hash()` para guardar las contraseñas, el inicio de sesión debe utilizar `bcrypt.compare()` para verificar las credenciales sin almacenar contraseñas en texto plano.
- **Importancia de las pruebas de seguridad:** Realizar pruebas automatizadas permite comprobar que las medidas implementadas funcionan correctamente y detectar posibles vulnerabilidades antes de integrar los cambios en la rama principal.


# Reflexion Tomas Mertian
- **No alcanza con validar la entrada:** si después pintás los datos con HTML crudo, el navegador ejecuta lo que venga. La solución fue armar el DOM con `createElement` y `textContent`, también en las tablas del panel y en el parámetro `vista` de la URL.
- **La CSP es una red de contención, no la única defensa:** configurar Helmet con `script-src 'self'` y `object-src 'none'` ayuda a limitar el daño, pero primero hay que escapar bien la salida.
- **CSRF necesita algo que el atacante no pueda leer:** un token aleatorio en cookie y en header, validado con comparación segura, más el chequeo de `Origin`/`Referer`. No alcanza con confiar en que la petición venga con la cookie de sesión.
- **La base también es parte de la seguridad:** la app tiene que conectarse con un usuario limitado (`origen_app`), no con el superusuario, y las contraseñas/secretos tienen que salir del entorno. Un secreto hardcodeado es un secreto que ya no es secreto.
- **Los tests y el checker sirven para no volver atrás:** correr la batería de seguridad y el análisis estático después de cada cambio mostró que un arreglo en el cliente no siempre alcanza; hay que revisar también lo que devuelve el servidor.

# Reflexion Renata Turani
- **No alcanza con pedir que inicien sesión:** si no revisás qué rol tiene cada usuario, un cliente común puede entrar al panel de administración o mandarse `"rol": "admin"` para darse permisos. En un proyecto real hay que chequear el rol (`requiereRol('admin')`) en todas las rutas del panel y controlar quién puede cambiar roles.
- **Nunca armar comandos con lo que escribe el usuario:** usar `exec` pegando directo el texto del `host` permite que cualquiera agregue `;` o `&&` y ejecute comandos en el servidor. La solución fue cambiarlo por `spawn` pasando los datos por separado y dejar una lista fija de servidores permitidos.
- **Revisar bien lo que se sube al servidor:** dejar que el usuario elija el nombre del archivo y suba cualquier extensión permite guardar archivos fuera de `uploads` usando `../` o subir un `.html` que después se ejecuta en la misma página. En un proyecto real hay que limitar el peso, verificar que sea una imagen de verdad y ponerle un nombre nuevo generado desde el servidor.
- **No mostrar datos internos en los errores ni dejar rutas de prueba abiertas:** devolver el `stack` del error o tener `/api/_diagnostico` sin protección deja a la vista rutas internas y la contraseña de la base de datos. Esos detalles tienen que quedar solo en la consola del servidor y los endpoints de diagnóstico se tienen que proteger o sacar antes de publicar la web.
- **Verificar todo con los tests después de cada arreglo:** correr los tests de seguridad y el checker ayudó a confirmar que los cambios frenaran los problemas sin romper las funciones que ya andaban bien.
