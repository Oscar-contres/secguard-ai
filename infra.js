/*
 * SecGuard AI · Reglas para archivos de infraestructura (Dockerfile, nginx.conf).
 * Son patrones de texto para una primera revisión, no un auditor completo.
 * Corre en el navegador y también en Node (para las pruebas).
 */
(function (global) {
  'use strict';

  var RISKY_PORTS = { '21': 'FTP', '22': 'SSH', '23': 'Telnet', '3389': 'RDP', '5900': 'VNC' };

  // Cabeceras que deberían declararse en cada bloque server de Nginx.
  var NGINX_HEADERS = [
    { name: 'Strict-Transport-Security', severity: 'medium', why: 'Sin HSTS, el navegador puede aceptar una versión HTTP del sitio.' },
    { name: 'Content-Security-Policy', severity: 'medium', why: 'Sin CSP, el sitio tiene menos defensas contra XSS.' },
    { name: 'X-Frame-Options', severity: 'low', why: 'Sin esta cabecera, la página puede embeberse en otro sitio (clickjacking).' },
    { name: 'X-Content-Type-Options', severity: 'low', why: 'Sin nosniff, el navegador puede interpretar mal el tipo de un archivo.' },
    { name: 'Referrer-Policy', severity: 'low', why: 'Sin esta cabecera, el navegador decide cuánta información se comparte al salir del sitio.' }
  ];

  var NGINX_RULES = [
    { severity: 'medium', re: /\bserver_tokens\s+on\s*;/, title: 'server_tokens on revela la versión de Nginx en cada respuesta.' },
    { severity: 'high', re: /\bautoindex\s+on\s*;/, title: 'autoindex on muestra el listado de archivos de los directorios.' },
    { severity: 'high', re: /\bTLSv1(\.1)?(?![\d.])/, title: 'Protocolo TLS antiguo (TLSv1 o TLSv1.1). Usa TLSv1.2 y TLSv1.3.' },
    { severity: 'high', re: /\bSSLv[23]\b/, title: 'SSLv2 y SSLv3 están rotos. Quítalos de ssl_protocols.' },
    { severity: 'medium', re: /\bclient_max_body_size\s+0\s*;/, title: 'Tamaño de petición sin límite (0). Define un valor razonable, por ejemplo 10m.' },
    { severity: 'medium', re: /\blimit_except\b[^;{]*\b(PUT|DELETE|TRACE|CONNECT)\b/, title: 'Se permiten métodos HTTP potencialmente peligrosos (PUT, DELETE, TRACE o CONNECT).' }
  ];

  function scanDockerfile(text) {
    var lines = text.split(/\r?\n/);
    var findings = [];
    var users = [];
    var hasHealthcheck = false;

    lines.forEach(function (raw, idx) {
      var line = raw.trim();
      if (!line || line.charAt(0) === '#') return;
      var n = idx + 1;
      var add = function (severity, title) {
        findings.push({ line: n, severity: severity, title: title });
      };

      var from = line.match(/^FROM\s+(\S+)/i);
      if (from && from[1].toLowerCase() !== 'scratch' && from[1].charAt(0) !== '$') {
        var image = from[1];
        if (/:latest$/i.test(image) || !/[:@]/.test(image)) {
          add('medium', 'Imagen base sin versión fija (' + image + '). Usa una etiqueta concreta o un digest.');
        }
      }

      if (/^USER\s+/i.test(line)) users.push(line.split(/\s+/)[1] || '');
      if (/^HEALTHCHECK\b/i.test(line)) hasHealthcheck = true;

      if (/^ADD\s+https?:\/\//i.test(line)) {
        add('high', 'ADD descarga un recurso remoto sin verificarlo. Usa COPY o valida un checksum.');
      }
      if (/\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/i.test(line)) {
        add('high', 'Descarga y ejecuta un script sin revisarlo (curl | sh).');
      }
      if (/^(ENV|ARG)\s+\S*(PASS|SECRET|TOKEN|API_?KEY|PWD|PRIVATE)\S*/i.test(line)) {
        add('high', 'Secreto definido con ENV o ARG. Queda guardado en la imagen. Usa secretos en tiempo de ejecución.');
      }
      if (/^EXPOSE\s+/i.test(line)) {
        line.split(/\s+/).slice(1).forEach(function (p) {
          var port = p.split('/')[0];
          if (RISKY_PORTS[port]) {
            add('high', 'Expone ' + RISKY_PORTS[port] + ' (puerto ' + port + '). Ese acceso no debería salir del contenedor.');
          }
        });
      }
      if (/^RUN\b/i.test(line) && /\bsudo\b/.test(line)) {
        add('medium', 'Usa sudo dentro de la imagen. El contenedor no debería necesitar más privilegios.');
      }
      if (/\bchmod\s+(-R\s+)?777\b/.test(line)) {
        add('medium', 'chmod 777 da permisos de escritura a cualquier usuario.');
      }
    });

    var lastUser = users.length ? users[users.length - 1] : '';
    if (!lastUser || lastUser.toLowerCase() === 'root' || lastUser === '0') {
      findings.push({ line: null, severity: 'medium', title: 'El contenedor corre como root. Define un usuario sin privilegios con USER.' });
    }
    if (!hasHealthcheck) {
      findings.push({ line: null, severity: 'low', title: 'Sin HEALTHCHECK. El orquestador no sabe si la aplicación sigue sana.' });
    }
    return findings;
  }

  function scanNginx(text) {
    var lines = text.split(/\r?\n/);
    var findings = [];

    lines.forEach(function (raw, idx) {
      var line = raw.replace(/#.*$/, '');
      NGINX_RULES.forEach(function (r) {
        if (r.re.test(line)) findings.push({ line: idx + 1, severity: r.severity, title: r.title });
      });
    });

    if (/\bserver\s*\{/.test(text)) {
      NGINX_HEADERS.forEach(function (h) {
        var declared = new RegExp('add_header\\s+' + h.name + '\\b', 'i').test(text);
        if (!declared) {
          findings.push({ line: null, severity: h.severity, title: 'Falta add_header ' + h.name + '. ' + h.why });
        }
      });
    }
    return findings;
  }

  function scanInfrastructure(text, kind) {
    var src = String(text || '');
    if (kind === 'dockerfile') return scanDockerfile(src);
    if (kind === 'nginx') return scanNginx(src);
    return [];
  }

  global.SecGuardInfra = { scanInfrastructure: scanInfrastructure };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = global.SecGuardInfra;
  }
})(typeof window !== 'undefined' ? window : globalThis);
