/*
 * SecGuard AI · Herramientas defensivas locales.
 * Todas las funciones de este archivo corren en el navegador.
 * Ninguna envía datos a un servidor.
 */
(function (global) {
  'use strict';

  var COMMON_WORDS = [
    'password', 'contraseña', 'contrasena', 'qwerty', 'letmein', 'welcome',
    'admin', 'iloveyou', 'dragon', 'monkey', 'football', 'sunshine',
    '123456', '12345678', 'abc123'
  ];
  var SEQUENCES = /(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwer|asdf|zxcv)/i;
  var REPEATS = /(.)\1{2,}/;

  var WEIGHTS = { high: 20, medium: 8, low: 3, ok: 0 };

  // ---------- Puntuación de riesgo ----------
  function riskScore(items) {
    var total = items.reduce(function (sum, it) {
      return sum + (WEIGHTS[it.severity] || 0);
    }, 0);
    return Math.min(100, total);
  }

  function riskLevel(score) {
    if (score < 30) return 'Bajo';
    if (score < 60) return 'Medio';
    return 'Alto';
  }

  // ---------- Contraseñas ----------
  function poolSize(pw) {
    var pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/[0-9]/.test(pw)) pool += 10;
    if (/[^A-Za-z0-9]/.test(pw)) pool += 32;
    return pool;
  }

  function strengthLabel(bits) {
    if (bits < 28) return 'Muy débil';
    if (bits < 40) return 'Débil';
    if (bits < 60) return 'Aceptable';
    if (bits < 80) return 'Fuerte';
    return 'Muy fuerte';
  }

  // Estimación orientativa: supone caracteres elegidos al azar.
  // Una palabra o frase real puede ser más débil de lo que indica.
  function analyzePassword(pw) {
    var len = pw.length;
    if (!len) return { length: 0, bits: 0, level: '—', percent: 0, issues: [] };

    var issues = [];
    var bits = len * Math.log2(poolSize(pw));
    var lower = pw.toLowerCase();

    if (COMMON_WORDS.some(function (w) { return lower.indexOf(w) !== -1; })) {
      bits = Math.min(bits, 14);
      issues.push({ severity: 'high', text: 'Contiene una palabra o patrón muy común. Los atacantes lo prueban primero.' });
    }
    if (REPEATS.test(pw)) {
      bits *= 0.75;
      issues.push({ severity: 'medium', text: 'Repite el mismo carácter tres o más veces seguidas.' });
    }
    if (SEQUENCES.test(pw)) {
      bits *= 0.8;
      issues.push({ severity: 'medium', text: 'Incluye una secuencia predecible, como 1234 o abcd.' });
    }
    if (len < 12) {
      issues.push({ severity: 'medium', text: 'Tiene menos de 12 caracteres. Se recomiendan 12 o más.' });
    }
    if (!/[A-Z]/.test(pw) || !/[a-z]/.test(pw)) {
      issues.push({ severity: 'low', text: 'Combina mayúsculas y minúsculas.' });
    }
    if (!/[0-9]/.test(pw)) {
      issues.push({ severity: 'low', text: 'No incluye números.' });
    }
    if (!/[^A-Za-z0-9]/.test(pw)) {
      issues.push({ severity: 'low', text: 'No incluye símbolos.' });
    }
    if (!issues.length) {
      issues.push({ severity: 'ok', text: 'Buena longitud y variedad. Aun así, debe ser única para cada cuenta.' });
    }

    bits = Math.round(bits);
    return {
      length: len,
      bits: bits,
      level: strengthLabel(bits),
      percent: Math.min(100, Math.round(bits / 90 * 100)),
      issues: issues
    };
  }

  // ---------- Secretos (sanitización local) ----------
  var SECRET_PATTERNS = [
    { type: 'clave de AWS', re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g },
    { type: 'clave tipo sk- (OpenAI o Anthropic)', re: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
    { type: 'token de GitHub', re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g },
    { type: 'clave de API de Google', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
    { type: 'token de Slack', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
    { type: 'JWT', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
    { type: 'clave privada', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, line: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
    { type: 'credencial asignada', re: /\b(password|passwd|pwd|secret|token|api[_-]?key|clave|contrase[ñn]a)\s*[:=]\s*["']?[^\s"']{6,}/gi }
  ];

  function findSecrets(text) {
    var found = [];
    SECRET_PATTERNS.forEach(function (p) {
      var hits = String(text || '').match(p.re);
      if (hits) found.push({ type: p.type, count: hits.length });
    });
    return found;
  }

  function redactSecrets(text) {
    var out = String(text || '');
    SECRET_PATTERNS.forEach(function (p) {
      out = out.replace(p.re, '[REDACTADO: ' + p.type + ']');
    });
    return out;
  }

  // ---------- Cabeceras HTTP ----------
  // Recibe el texto pegado ("nombre: valor" por línea) y devuelve un mapa
  // con el nombre en minúsculas y una lista de valores (para Set-Cookie repetidas).
  function parseHeaders(raw) {
    var map = {};
    String(raw || '').split(/\r?\n/).forEach(function (line) {
      var i = line.indexOf(':');
      if (i <= 0) return;
      var name = line.slice(0, i).trim().toLowerCase();
      if (!/^[a-z0-9-]+$/.test(name)) return;
      (map[name] = map[name] || []).push(line.slice(i + 1).trim());
    });
    return map;
  }

  function evaluateHeaders(map, opts) {
    opts = opts || {};
    var checks = [];

    function get(name) { return map[name] ? map[name][0] : null; }
    function add(id, severity, label, detail) {
      checks.push({ id: id, severity: severity, label: label, detail: detail });
    }

    if (typeof opts.https === 'boolean') {
      if (opts.https) add('https', 'ok', 'HTTPS', 'La URL usa conexión cifrada.');
      else add('https', 'high', 'HTTPS', 'La URL usa HTTP sin cifrar. Redirige todo el tráfico a HTTPS.');
    }

    var hsts = get('strict-transport-security');
    if (!hsts) {
      add('hsts', 'high', 'Strict-Transport-Security', 'Ausente. Sin HSTS, un visitante puede terminar en una versión HTTP del sitio.');
    } else {
      var m = hsts.match(/max-age=(\d+)/i);
      if (m && parseInt(m[1], 10) >= 15552000) add('hsts', 'ok', 'Strict-Transport-Security', 'Presente con duración adecuada (180 días o más).');
      else add('hsts', 'medium', 'Strict-Transport-Security', 'Presente, pero con max-age bajo. Se recomiendan al menos 15552000 segundos.');
    }

    var csp = get('content-security-policy');
    if (!csp) {
      add('csp', 'high', 'Content-Security-Policy', 'Ausente. Es la defensa principal contra XSS y la carga de recursos no autorizados.');
    } else if (/unsafe-inline|unsafe-eval|\*/.test(csp)) {
      add('csp', 'medium', 'Content-Security-Policy', 'Presente, pero permite recursos inseguros (unsafe-inline, unsafe-eval o comodines *).');
    } else {
      add('csp', 'ok', 'Content-Security-Policy', 'Política de contenido definida.');
    }

    var xfo = get('x-frame-options');
    var frameAncestors = !!(csp && /frame-ancestors/i.test(csp));
    if (xfo || frameAncestors) {
      add('frame', 'ok', 'Protección contra clickjacking', 'Definida mediante ' + (frameAncestors ? 'frame-ancestors' : 'X-Frame-Options') + '.');
    } else {
      add('frame', 'medium', 'Protección contra clickjacking', 'Falta X-Frame-Options o frame-ancestors en la política CSP.');
    }

    if ((get('x-content-type-options') || '').toLowerCase() === 'nosniff') {
      add('nosniff', 'ok', 'X-Content-Type-Options', 'Configurada como nosniff.');
    } else {
      add('nosniff', 'medium', 'X-Content-Type-Options', 'Falta. nosniff evita que el navegador adivine el tipo de los archivos.');
    }

    if (get('referrer-policy')) {
      add('referrer', 'ok', 'Referrer-Policy', 'Controla qué información de la página se comparte al salir del sitio.');
    } else {
      add('referrer', 'medium', 'Referrer-Policy', 'Falta. El navegador decide por defecto cuánta información se comparte.');
    }

    if (get('permissions-policy')) {
      add('permissions', 'ok', 'Permissions-Policy', 'Restringe funciones del navegador como cámara, micrófono o geolocalización.');
    } else {
      add('permissions', 'low', 'Permissions-Policy', 'No está definida. Conviene limitar las funciones del navegador a lo que la página necesita.');
    }

    var cookies = map['set-cookie'] || [];
    if (cookies.length) {
      var weak = cookies.filter(function (c) {
        var s = c.toLowerCase();
        return s.indexOf('secure') === -1 || s.indexOf('httponly') === -1 || s.indexOf('samesite') === -1;
      });
      if (weak.length) add('cookies', 'medium', 'Cookies', weak.length + ' de ' + cookies.length + ' no declaran Secure, HttpOnly y SameSite.');
      else add('cookies', 'ok', 'Cookies', 'Todas declaran Secure, HttpOnly y SameSite.');
    }

    var tech = get('server') || get('x-powered-by');
    if (tech) {
      add('tech', 'low', 'Divulgación de tecnología', 'Revela software: "' + tech + '". Ocultarlo reduce la información útil para un atacante.');
    } else {
      add('tech', 'ok', 'Divulgación de tecnología', 'No se revelan software ni versión en las cabeceras.');
    }

    return { checks: checks, risk: riskScore(checks) };
  }

  // ---------- Código: escaneo local rápido ----------
  // Patrones de texto, no un analizador completo. Sirven como primer filtro.
  var CODE_RULES = {
    javascript: [
      { severity: 'high', title: 'eval() ejecuta texto como código', re: /\beval\s*\(/ },
      { severity: 'high', title: 'innerHTML con contenido dinámico (posible XSS)', re: /\.innerHTML\s*\+?=(?!=)/ },
      { severity: 'medium', title: 'document.write puede insertar contenido no confiable', re: /document\.write\s*\(/ },
      { severity: 'medium', title: 'Redirección con datos de la URL sin validar', re: /location(\.href)?\s*=.*(location\.search|params|query)/ }
    ],
    python: [
      { severity: 'high', title: 'eval() o exec() con texto dinámico', re: /\b(eval|exec)\s*\(/ },
      { severity: 'high', title: 'subprocess con shell=True (inyección de comandos)', re: /subprocess\.\w+\(.*shell\s*=\s*True/ },
      { severity: 'high', title: 'pickle.load(s) con datos no confiables', re: /pickle\.loads?\s*\(/ },
      { severity: 'high', title: 'Consulta SQL armada con f-string, % o +', re: /\.execute(many)?\s*\(\s*(f["']|["'][^"']*["']\s*(%|\+)|[^,)]*\+)/ },
      { severity: 'medium', title: 'MD5 o SHA1 usados como hash', re: /hashlib\.(md5|sha1)\s*\(/ }
    ],
    sql: [
      { severity: 'medium', title: 'Procedimiento que ejecuta comandos del sistema', re: /xp_cmdshell/i }
    ],
    php: [
      { severity: 'high', title: 'Datos de la petición en una consulta SQL sin preparar', re: /\$_(GET|POST|REQUEST|COOKIE)\b.*\b(query|mysql_query|mysqli_query)\s*\(/ },
      { severity: 'high', title: 'Ejecución de comandos o código dinámico', re: /\b(eval|system|exec|shell_exec|passthru)\s*\(/ },
      { severity: 'high', title: 'Datos de la petición impresos sin escapar (XSS)', re: /\becho\s+\$_(GET|POST|REQUEST)/ },
      { severity: 'medium', title: 'Inclusión de archivo con datos del usuario', re: /\b(include|require)(_once)?\s*\(?\s*\$_(GET|POST|REQUEST)/ }
    ],
    env: [
      { severity: 'medium', title: 'DEBUG activado. No debe quedar encendido en producción.', re: /^\s*(export\s+)?((APP|FLASK)_)?DEBUG\s*=\s*["']?(true|1|on|yes)\b/i },
      { severity: 'high', title: 'Contraseña por defecto o trivial en la configuración.', re: /(PASS(WORD)?|PWD)\w*\s*=\s*["']?(admin|password|changeme|123456|secret|root|test)["']?\s*$/i }
    ]
  };

  function quickCodeScan(code, lang) {
    var findings = [];
    var lines = String(code || '').split(/\r?\n/);
    var rules = CODE_RULES[lang] || [];

    lines.forEach(function (line, idx) {
      rules.forEach(function (r) {
        if (r.re.test(line)) findings.push({ line: idx + 1, severity: r.severity, title: r.title });
      });
      SECRET_PATTERNS.forEach(function (p) {
        if (line.match(p.line || p.re)) {
          findings.push({ line: idx + 1, severity: 'high', title: 'Posible ' + p.type + ' en el código. Conviene rotarla.' });
        }
      });
    });

    return findings;
  }

  global.SecGuardTools = {
    riskScore: riskScore,
    riskLevel: riskLevel,
    analyzePassword: analyzePassword,
    findSecrets: findSecrets,
    redactSecrets: redactSecrets,
    parseHeaders: parseHeaders,
    evaluateHeaders: evaluateHeaders,
    quickCodeScan: quickCodeScan
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = global.SecGuardTools;
  }
})(typeof window !== 'undefined' ? window : globalThis);
