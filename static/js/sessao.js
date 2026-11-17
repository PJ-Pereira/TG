/* RNF02 – Sessão segura
 * - Se o usuário ficar sem mexer na página pelo tempo configurado, ele é desconectado.
 * - Enquanto o usuário estiver ativo na página (digitando um relatório, por exemplo), o
 *   servidor é avisado no máximo 1 vez por minuto, para a sessão não expirar no meio da digitação.
 */
(function () {
  var body = document.body;
  var minutos = parseInt(body.dataset.inatividade || '10', 10);
  var limite = minutos * 60 * 1000;
  var urlPing = body.dataset.ping;
  var urlSair = body.dataset.sair;
  var meta = document.querySelector('meta[name="csrf-token"]');
  var token = meta ? meta.content : '';
  var ultimaAtividade = Date.now();
  var ultimoPing = Date.now();

  function atividade() {
    ultimaAtividade = Date.now();
    if (Date.now() - ultimoPing > 60 * 1000) {
      ultimoPing = Date.now();
      fetch(urlPing, { method: 'POST', headers: { 'X-CSRFToken': token }, credentials: 'same-origin' })
        .then(function (r) { if (r.status === 401) { window.location.href = urlSair; } })
        .catch(function () {});
    }
  }

  ['keydown', 'mousedown', 'mousemove', 'touchstart', 'scroll', 'input'].forEach(function (ev) {
    document.addEventListener(ev, atividade, { passive: true });
  });

  setInterval(function () {
    if (Date.now() - ultimaAtividade >= limite) { window.location.href = urlSair; }
  }, 15 * 1000);
})();
