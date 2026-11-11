# SecGuard AI

Auditor defensivo de ciberseguridad para el navegador. Revisa fragmentos de código, cabeceras HTTP y la fuerza de contraseñas, y muestra los resultados en una consola con puntuación de riesgo. El asistente de IA se consulta a través de un servidor propio que guarda la clave y fija el encuadre defensivo.

## Estructura

```
secguard/
├── server.js            Servidor Express: proxy de la IA, límites de uso y archivos estáticos
├── lib/sanitize.js      Validación y redacción de texto (sin dependencias)
├── test/sanitize.test.js Pruebas de validación y redacción
├── index.html           Interfaz: barra superior, accesos rápidos, paneles y consola
├── assets/logo.svg      Logotipo (escudo con prompt >_)
├── css/style.css        Estilos (paleta carbón, cian y verde de terminal)
├── js/security.js       Lógica local: contraseñas, secretos, cabeceras, escaneo de código
├── js/intent.js         Filtro de intención ofensiva (navegador y servidor)
├── js/infra.js          Reglas para Dockerfile y nginx.conf
├── js/script.js         Flujo de la interfaz, llamada a la IA, historial y exportación
├── package.json
├── .env.example         Plantilla de configuración (copiar a .env)
└── README.md
```

## Puesta en marcha

Requiere Node.js 20 o superior.

```bash
cd secguard
npm install
cp .env.example .env     # en Windows: copy .env.example .env
```

Edita `.env` y escribe tu clave en `API_KEY`. Después:

```bash
npm start
```

Abre http://127.0.0.1:8080 en el navegador. Con `npm test` corren las pruebas de validación, del filtro ofensivo y de las reglas de infraestructura.

## Configuración (`.env`)

| Variable | Para qué sirve | Valor por defecto |
|---|---|---|
| `API_KEY` | Clave de la API de IA. Obligatoria. Solo la lee el servidor. | — |
| `MODEL` | Modelo que responde las consultas. | `claude-sonnet-5-5` |
| `HOST` / `PORT` | Dirección y puerto del servidor. | `127.0.0.1` / `8080` |
| `RATE_LIMIT_PER_MINUTE` | Consultas por minuto y por IP. | `10` |
| `MAX_CONCURRENT` | Consultas a la IA procesándose a la vez. | `3` |
| `MAX_MESSAGE_CHARS` | Tamaño máximo de una consulta. | `12000` |
| `TRUST_PROXY` | Usar `true` solo detrás de un proxy o balanceador de confianza. | `false` |

## Cómo protege el servidor

- **Clave fuera del navegador.** La clave vive en `.env`. El navegador solo envía el texto a `POST /api/analyze`.
- **Encuadre fijo.** El system prompt defensivo está en `server.js`. El campo `system` que envíe el navegador se ignora. Las reglas le indican al modelo que el material analizado son datos y no órdenes.
- **Límite de uso.** Máximo de consultas por minuto y por IP, y tope de consultas simultáneas. Así se evitan automatizaciones y sobrecostos.
- **Validación del texto.** Se exige texto, no vacío y con tamaño máximo. Se quitan caracteres de control e invisibles que sirven para ocultar contenido.
- **Filtro ofensivo en el servidor.** Si una consulta pide atacar o vulnerar sistemas ajenos, responde 422 aunque el navegador no la haya frenado.
- **Redacción en el servidor.** Si llega una clave, token o contraseña, se reemplaza por un marcador antes de enviarla a la IA. La consola solo registra el tipo de dato redactado, nunca el valor.
- **Cabeceras de seguridad.** Helmet aplica una Content-Security-Policy que coincide con la de la interfaz.
- **Archivos protegidos.** Solo se publican `index.html`, `css/`, `js/` y `assets/`. `server.js`, `.env` y `lib/` no son accesibles desde el navegador.
- **Errores sin detalles.** Si la API de IA falla, el cliente recibe un mensaje genérico. El cuerpo de la respuesta de error no se reenvía, porque puede repetir datos de la consulta.

## Qué funciona sin servidor

Estas partes corren completas en el navegador y no envían datos a ningún lado:

- **Contraseñas**: longitud, entropía estimada y patrones débiles. La contraseña no se escribe en la consola ni en los reportes.
- **Cabeceras HTTP**: evalúa las cabeceras que pegues (HSTS, CSP, clickjacking, nosniff, Referrer-Policy, cookies, divulgación de tecnología). No contacta el sitio, porque el navegador no puede leer cabeceras de otros dominios.
- **Escaneo de código**: patrones frecuentes en Python, JavaScript, SQL y PHP (eval, inyección SQL con formato de texto, innerHTML, shell=True, entre otros).
- **Sanitización**: antes de enviar cualquier texto busca claves de API, tokens, JWT, claves privadas y credenciales asignadas. Puedes redactarlas o cancelar el envío.
- **Reporte**: descarga en .txt. El PDF se activa si jsPDF se carga desde su CDN.
- **Infraestructura**: revisa Dockerfile (usuario root, imágenes sin versión fija, ADD remoto, puertos peligrosos, secretos en ENV) y nginx.conf (server_tokens, autoindex, TLS antiguo, cabeceras faltantes). También revisa `.env` buscando DEBUG activado y contraseñas triviales.
- **Historial de sesión**: guarda las últimas consultas en sessionStorage, con su puntuación de riesgo. Se borra al cerrar la pestaña. Nunca guarda el texto original ni contraseñas.
- **Filtro ofensivo**: frena peticiones para atacar, vulnerar o engañar a personas o sistemas ajenos. Puede dar falsos positivos; en ese caso, reformula la consulta de forma defensiva.

## Uso responsable

Usa SecGuard solo sobre sistemas propios o sobre los que tengas autorización explícita. La herramienta está pensada para encontrar y corregir fallos, no para explotarlos. El asistente rechaza las peticiones ofensivas, pero la responsabilidad de su uso es de quien la opera.

## Límites conocidos

- Los patrones de código son un primer filtro. No reemplazan una revisión manual ni un análisis SAST completo.
- La entropía es una estimación. Una palabra o frase real puede ser más débil de lo que indica el número.
- La puntuación de riesgo resume los hallazgos encontrados. Un puntaje bajo no significa que el sistema sea seguro.
- El control de tasa vive en memoria. Si ejecutas varias instancias, cada una lleva su propia cuenta.
