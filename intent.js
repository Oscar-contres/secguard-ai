/*
 * SecGuard AI · Filtro local de intención ofensiva.
 * Frena peticiones para atacar, vulnerar o engañar a personas o sistemas ajenos.
 * Las preguntas defensivas (cómo proteger, cómo detectar, qué hacer si...) pasan sin bloqueo.
 * Corre en el navegador y también en el servidor (server.js) como segunda barrera.
 * Es un filtro por patrones: puede dar falsos positivos. En ese caso, reformular la consulta de forma defensiva.
 */
(function (global) {
  'use strict';

  var REASON = 'Esta consulta pide ayuda para atacar, vulnerar o engañar a personas o sistemas ajenos. SecGuard solo ayuda a defender. Si quieres protegerte, puedo explicar cómo detectar o prevenir ese ataque.';

  // Verbos de ataque.
  var ATTACK = /\b(hackear|hackea|hackee|hackeo|hack|vulnerar|explotar|exploit|atacar|crackear|crackea|robar|tumbar|bypass|evadir|suplantar|espiar|secuestrar)\b|\b(entrar|acceder|ingresar)\s+(a|en)\s+(la\s+|su\s+|una\s+)?cuenta\b/i;

  // Señales de que el objetivo no es propio.
  var TARGET = /\b(ajen[oa]s?|de (otr[oa]s?|alguien|terceros?)|sin (su |el |tu )?(permiso|autorizaci[oó]n|consentimiento)|(de|del)\s+(un|una|mi|mis|el|la|los|las)?\s*\b(banco|vecin[oa]s?|jefe|ex|novi[oa]s?|espos[oa]s?|compañer[oa]s?|gobierno|colegio|escuela|hospital|tienda|plataforma|competidor(a|es)?)\b|https?:\/\/|www\.|\b[a-z0-9-]+\.(com|net|org|mx|ve|co|io|es|gob|edu|info)\b)/i;

  // Verbos que piden crear o programar algo.
  var CREATE = /\b(crea(r|me)?|escrib(e|ir|eme)|program(a|ar|ame)|haz(me)?|mont(a|ar|ame)|d[aá]me)\b/i;

  // Herramientas o técnicas ofensivas.
  var MALWARE = /\b(keylogger|ransomware|troyano|botnet|rootkit|gusano|malware|ddos|phishing)\b/i;
  var PHISH_PAGE = /\b(p[aá]gina|sitio|formulario|login|inicio de sesi[oó]n|correo)\b.{0,40}\b(falso|falsa|clon|clonad[oa]|id[eé]ntic[oa]|parecid[oa])\b|\b(falso|falsa|clonad[oa])\b.{0,40}\b(p[aá]gina|sitio|formulario|login|inicio de sesi[oó]n)\b/i;
  var BRUTE = /\bfuerza bruta\b|\bbrute[- ]?force\b/i;

  // Robo de credenciales o datos.
  var COMO = /\bc[oó]mo\b/i;
  var STEAL = /\b(robar|capturar|interceptar)\b.{0,30}\b(contrase[ñn]as?|credenciales|tarjetas?|cookies|sesiones|cuentas|datos( bancarios| personales)?)\b/i;

  function detectOffensiveIntent(text) {
    var t = String(text || '');
    var attack = ATTACK.test(t);
    var target = TARGET.test(t);
    var create = CREATE.test(t);

    var blocked =
      (attack && target) ||
      (create && (MALWARE.test(t) || PHISH_PAGE.test(t) || BRUTE.test(t))) ||
      ((create || COMO.test(t)) && STEAL.test(t));

    return blocked ? { blocked: true, reason: REASON } : { blocked: false, reason: '' };
  }

  global.SecGuardIntent = { detectOffensiveIntent: detectOffensiveIntent };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = global.SecGuardIntent;
  }
})(typeof window !== 'undefined' ? window : globalThis);
