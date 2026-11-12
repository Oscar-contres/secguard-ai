/*
 * SecGuard AI · Interfaz, flujo de consultas y exportación.
 *
 * Seguridad de la propia herramienta:
 * - La consola escribe con textContent. La respuesta de la IA nunca se interpreta como HTML.
 * - La clave de la API de IA no vive aquí. El navegador solo envía el texto a POST /api/analyze.
 *   El encuadre defensivo está fijo en server.js y el navegador no puede cambiarlo.
 * - Antes de enviar algo a la IA se buscan claves, contraseñas y tokens.
 */
(function () {
  'use strict';

  var T = window.SecGuardTools;
  var Intent = window.SecGuardIntent;
  var Infra = window.SecGuardInfra;
  var INFRA_KINDS = ['dockerfile', 'nginx'];

  var CONFIG = {
    endpoint: '/api/analyze',
    timeoutMs: 45000
  };

  var $ = function (id) { return document.getElementById(id); };
  var consoleEl = $('console');
  var typewriterEl = $('typewriter');
  var gaugeEl = $('gauge-value');
  var scoreEl = $('risk-score');
  var levelEl = $('risk-level');
  var exportTxtBtn = $('export-txt');
  var exportPdfBtn = $('export-pdf');
  var dialog = $('sanitize-dialog');
  var GAUGE_LEN = 314.16;
  var reduceMotion = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);

  var reportLines = [];
  var currentRisk = null;
  var printChain = Promise.resolve();

  var SEV_LABEL = { high: 'CRÍTICO', medium: 'AVISO', low: 'INFO', ok: 'OK' };
  var SEV_CLASS = { high: 'err', medium: 'warn', low: 'info', ok: 'ok' };
  var ISSUE_CLASS = { high: 'bad', medium: 'warn', low: '', ok: 'ok' };

  // ---------- Consola ----------
  function addLine(text, cls) {
    var p = document.createElement('p');
    p.className = 'line' + (cls ? ' ' + cls : '');
    p.textContent = text;
    consoleEl.appendChild(p);
    consoleEl.scrollTop = consoleEl.scrollHeight;
    return p;
  }

  function typeLine(text, cls) {
    return new Promise(function (resolve) {
      var p = addLine('', cls);
      p.classList.add('cursor');
      var i = 0;
      (function tick() {
        i += 2;
        p.textContent = text.slice(0, i);
        consoleEl.scrollTop = consoleEl.scrollHeight;
        if (i < text.length) {
          setTimeout(tick, 12);
        } else {
          p.classList.remove('cursor');
          resolve();
        }
      })();
    });
  }

  // Escribe en orden, aunque haya animaciones en curso.
  function write(text, cls) {
    reportLines.push(text);
    var animate = typewriterEl.checked && !reduceMotion;
    printChain = printChain.then(function () {
      return animate ? typeLine(text, cls) : addLine(text, cls);
    });
    return printChain;
  }

  function writeBlock(text, cls) {
    String(text).split('\n').forEach(function (line) { write(line, cls); });
  }

  function startBusy(label) {
    var p = addLine(label, 'muted');
    var dots = 0;
    var id = setInterval(function () {
      dots = (dots + 1) % 4;
      p.textContent = label + '.'.repeat(dots);
    }, 400);
    return function stop() {
      clearInterval(id);
      p.remove();
    };
  }

  // ---------- Medidor de riesgo ----------
  function setRisk(score) {
    currentRisk = score;
    var color = score < 30 ? 'var(--green)' : score < 60 ? 'var(--yellow)' : 'var(--red)';
    gaugeEl.style.strokeDashoffset = String(GAUGE_LEN * (1 - score / 100));
    gaugeEl.style.stroke = color;
    scoreEl.textContent = score + ' / 100';
    levelEl.textContent = 'Riesgo ' + T.riskLevel(score).toLowerCase();
    levelEl.style.color = color;
  }

  function enableExport() {
    exportTxtBtn.disabled = false;
    exportPdfBtn.disabled = !(window.jspdf && window.jspdf.jsPDF);
  }

  // ---------- Sanitización antes de enviar ----------
  function confirmSanitize(found) {
    return new Promise(function (resolve) {
      var list = $('sd-list');
      list.textContent = '';
      found.forEach(function (f) {
        var li = document.createElement('li');
        li.className = 'bad';
        li.textContent = f.type + (f.count > 1 ? ' (' + f.count + ')' : '');
        list.appendChild(li);
      });

      var redactBtn = $('sd-redact');
      var cancelBtn = $('sd-cancel');
      dialog.hidden = false;
      redactBtn.focus();

      function done(choice) {
        dialog.hidden = true;
        redactBtn.removeEventListener('click', onRedact);
        cancelBtn.removeEventListener('click', onCancel);
        document.removeEventListener('keydown', onKey);
        resolve(choice);
      }
      function onRedact() { done('redact'); }
      function onCancel() { done('cancel'); }
      function onKey(e) { if (e.key === 'Escape') done('cancel'); }

      redactBtn.addEventListener('click', onRedact);
      cancelBtn.addEventListener('click', onCancel);
      document.addEventListener('keydown', onKey);
    });
  }

  // Devuelve el texto listo para enviar, o null si el usuario cancela.
  async function guard(text) {
    var found = T.findSecrets(text);
    if (!found.length) return text;
    var choice = await confirmSanitize(found);
    if (choice !== 'redact') return null;
    return T.redactSecrets(text);
  }

  // ---------- Bloqueo local de intención ofensiva ----------
  // Primero se frena la intención ofensiva; después se redacta lo sensible.
  async function prepare(raw) {
    var intent = Intent.detectOffensiveIntent(raw);
    if (intent.blocked) {
      write('[BLOQUEADO] ' + intent.reason, 'err');
      return null;
    }
    return guard(raw);
  }

  // ---------- Historial de la sesión (sessionStorage) ----------
  // Guarda solo la salida que ya se mostró en la consola.
  // Nunca guarda el texto original ni las contraseñas, y se borra al cerrar la pestaña.
  var HISTORY_KEY = 'secguard-historial';
  var HISTORY_MAX = 20;
  var historyListEl = $('history-list');

  function readHistory() {
    try {
      var data = JSON.parse(sessionStorage.getItem(HISTORY_KEY) || '[]');
      return Array.isArray(data) ? data : [];
    } catch (e) {
      return [];
    }
  }

  function saveHistory(list) {
    try {
      sessionStorage.setItem(HISTORY_KEY, JSON.stringify(list));
    } catch (e) {}
  }

  function renderHistory() {
    var list = readHistory();
    historyListEl.textContent = '';
    if (!list.length) {
      var empty = document.createElement('li');
      empty.className = 'hint';
      empty.textContent = 'Aún no hay consultas en esta sesión.';
      historyListEl.appendChild(empty);
      return;
    }
    list.forEach(function (entry) {
      var li = document.createElement('li');
      var btn = document.createElement('button');
      var when = new Date(entry.time).toLocaleTimeString('es', { hour: '2-digit', minute: '2-digit' });
      btn.type = 'button';
      btn.className = 'history-item';
      btn.textContent = when + ' · ' + entry.title + (typeof entry.risk === 'number' ? ' · riesgo ' + entry.risk : '');
      btn.addEventListener('click', function () { restoreEntry(entry); });
      li.appendChild(btn);
      historyListEl.appendChild(li);
    });
  }

  function recordHistory(title, start, risk) {
    var lines = reportLines.slice(start, start + 300).map(function (l) {
      return String(l).slice(0, 2000);
    });
    var list = readHistory();
    list.unshift({ time: new Date().toISOString(), title: title, risk: risk, lines: lines });
    saveHistory(list.slice(0, HISTORY_MAX));
    consoleEl.textContent = '';
    reportLines = lines.slice();
    lines.forEach(function (line) { addLine(line, ''); });
    if (typeof entry.risk === 'number') setRisk(entry.risk);
    enableExport();
  }

  // ---------- Llamada a la IA (a través del proxy del servidor) ----------
  async function askAI(message) {
    var controller = new AbortController();
    var timer = setTimeout(function () { controller.abort(); }, CONFIG.timeoutMs);
    try {
      var res = await fetch(CONFIG.endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: message }),
        signal: controller.signal,
        credentials: 'same-origin'
      });
      var data = await res.json().catch(function () { return {}; });
      if (!res.ok) throw new Error(data.error || 'El servidor respondió con error ' + res.status + '.');
      return String(data.reply || '');
    } catch (err) {
      if (err.name === 'AbortError') throw new Error('La IA tardó demasiado en responder.');
      if (err.name === 'TypeError') throw new Error('No hay conexión con el servidor de SecGuard.');
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  function parseRisk(text) {
    var m = text.match(/RIESGO:\s*(\d{1,3})/i);
    return m ? Math.min(100, parseInt(m[1], 10)) : null;
  }

  async function runAI(message, label) {
    var stop = startBusy(label);
    try {
  }

  // ---------- Módulos ----------
  async function sendChat() {
    var input = $('chat-input');
    var raw = input.value.trim();
    if (!raw) return;
    var start = reportLines.length;
    currentRisk = null;
    var text = await prepare(raw);
    if (text === null) return;
    input.value = '';
    write('$ secguard consulta --modo=defensivo', 'info');
    await runAI(text, 'Analizando vulnerabilidades');
    recordHistory('consulta al asistente', start, currentRisk);
  }

  async function auditCode() {
    var raw = $('code-input').value;
    if (!raw.trim()) {
      write('[AVISO] Pega un fragmento de código antes de auditar.', 'warn');
      return;
    }
    var start = reportLines.length;
    currentRisk = null;
    var code = await prepare(raw);
    if (code === null) return;

    var lang = $('code-lang').value;
    write('$ secguard audit --lang=' + lang, 'info');

    var findings = INFRA_KINDS.indexOf(lang) !== -1
      ? Infra.scanInfrastructure(code, lang).concat(T.quickCodeScan(code, 'env'))
      : T.quickCodeScan(code, lang);
    if (!findings.length) {
      write('Análisis local: no se encontraron patrones de riesgo conocidos.', 'ok');
      write('El escáner local solo revisa patrones de texto conocidos. Que no aparezca un hallazgo no significa que el código sea seguro.', 'muted');
    }
    findings.forEach(function (f) {
      var where = f.line ? 'línea ' + f.line + ': ' : '';
      write('[' + SEV_LABEL[f.severity] + '] ' + where + f.title, SEV_CLASS[f.severity]);
    });
    setRisk(T.riskScore(findings));
    enableExport();

    await runAI(
      'Revisa este fragmento de ' + lang + ', detecta fallos de seguridad y devuelve la versión corregida:\n' + code,
      'Analizando vulnerabilidades'
    );
    recordHistory('auditoría de ' + lang, start, currentRisk);
  }

  function auditHeaders() {
    var raw = $('headers-input').value;
    if (!raw.trim()) {
      write('[AVISO] Pega las cabeceras de respuesta primero.', 'warn');
      return;
    }
    if (!T.looksLikeHeaders(raw)) {
      write('[AVISO] El texto no parece una lista de cabeceras. Cada línea debe tener el formato "nombre: valor". Cópialas desde la pestaña Red de las herramientas de desarrollador.', 'warn');
      return;
    }
    var url = $('headers-url').value.trim();
    var opts = {};
    if (url) opts.https = /^https:\/\//i.test(url);

    var start = reportLines.length;
    currentRisk = null;
    write('$ secguard headers --target=' + (url || 'entrada-manual'), 'info');
    var result = T.evaluateHeaders(T.parseHeaders(raw), opts);
    result.checks.forEach(function (c) {
      write('[' + SEV_LABEL[c.severity] + '] ' + c.label + ': ' + c.detail, SEV_CLASS[c.severity]);
    });
    setRisk(result.risk);
    write('Análisis basado solo en las cabeceras que pegaste. No se contactó el sitio.', 'muted');
    enableExport();
    recordHistory('cabeceras HTTP', start, currentRisk);
  }

  function updatePassword() {
    var pw = $('pw-input').value;
    var r = T.analyzePassword(pw);
    var fill = $('pw-fill');

    fill.style.width = r.percent + '%';
    fill.style.backgroundColor = r.bits >= 60 ? 'var(--green)' : r.bits >= 40 ? 'var(--yellow)' : 'var(--red)';
    $('pw-len').textContent = String(r.length);
    $('pw-bits').textContent = r.bits + ' bits';
    $('pw-level').textContent = r.level;

    var list = $('pw-issues');
    list.textContent = '';
    r.issues.forEach(function (issue) {
      var li = document.createElement('li');
      li.className = ISSUE_CLASS[issue.severity];
      li.textContent = issue.text;
      list.appendChild(li);
    });
    // La contraseña nunca se escribe en la consola ni en el reporte.
  }

  // ---------- Pestañas y accesos rápidos ----------
  var tabs = Array.prototype.slice.call(document.querySelectorAll('.tab'));
  var FOCUS_TARGET = { chat: 'chat-input', code: 'code-input', headers: 'headers-input', password: 'pw-input' };

  function openTab(name) {
    tabs.forEach(function (t) {
      var key = t.getAttribute('data-tab');
      var on = key === name;
      t.setAttribute('aria-selected', String(on));
      t.tabIndex = on ? 0 : -1;
      $('pane-' + key).hidden = !on;
    });
  }

  tabs.forEach(function (t) {
    t.addEventListener('click', function () {
      openTab(t.getAttribute('data-tab'));
    });
  });

  document.querySelectorAll('[data-open]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var name = btn.getAttribute('data-open');
      openTab(name);
      $('pane-' + name).scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'nearest' });
      $(FOCUS_TARGET[name]).focus({ preventScroll: true });
    });
  });

  document.querySelectorAll('.chip').forEach(function (chip) {
    chip.addEventListener('click', function () {
      var input = $('chat-input');
      input.value = chip.getAttribute('data-prompt');
      input.focus();
    });
  });

  // ---------- Exportación ----------
  function reportText() {
    var head = [
      'REPORTE EJECUTIVO DE CIBERSEGURIDAD',
      'Generado por SecGuard AI · ' + new Date().toLocaleString('es'),
      'Puntuación de riesgo: ' + scoreEl.textContent,
      '',
      'Uso defensivo. Verifica cada hallazgo antes de aplicar cambios.',
      '----------------------------------------------------------------'
    ];
    return head.concat(reportLines).join('\n');
  }

  function download(filename, blob) {
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  exportTxtBtn.addEventListener('click', function () {
    download('reporte-secguard.txt', new Blob([reportText()], { type: 'text/plain;charset=utf-8' }));
  });

  exportPdfBtn.addEventListener('click', function () {
    if (!(window.jspdf && window.jspdf.jsPDF)) return;
    var doc = new window.jspdf.jsPDF({ unit: 'pt', format: 'a4' });
    var margin = 48;
    var width = doc.internal.pageSize.getWidth() - margin * 2;
    var limit = doc.internal.pageSize.getHeight() - margin;
    var y = margin;
    doc.setFont('courier', 'normal');
    doc.setFontSize(9);
    doc.splitTextToSize(reportText(), width).forEach(function (line) {
      if (y > limit) {
        doc.addPage();
        y = margin;
      }
      doc.text(line, margin, y);
      y += 13;
    });
    doc.save('reporte-secguard.pdf');
  });

  // ---------- Eventos ----------
  $('history-clear').addEventListener('click', function () {
    try { sessionStorage.removeItem(HISTORY_KEY); } catch (e) {}
    renderHistory();
  });
  renderHistory();
  $('chat-send').addEventListener('click', sendChat);
  $('chat-input').addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) sendChat();
  });
  $('code-send').addEventListener('click', auditCode);
  $('headers-send').addEventListener('click', auditHeaders);
  $('pw-input').addEventListener('input', updatePassword);
  $('pw-toggle').addEventListener('click', function () {
    var input = $('pw-input');
    var reveal = input.type === 'password';
    input.type = reveal ? 'text' : 'password';
    this.textContent = reveal ? 'Ocultar' : 'Mostrar';
    this.setAttribute('aria-pressed', String(reveal));
  });
})();
