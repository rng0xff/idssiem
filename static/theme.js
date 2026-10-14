/* Applied before first paint so dark mode does not flash. Same behaviour as the TARA Workbench: light by default. */
try { if (localStorage.getItem('fleet-ids.theme') === 'dark') document.documentElement.dataset.theme = 'dark'; } catch (e) { /* storage blocked */ }
document.addEventListener('DOMContentLoaded', function () {
  var b = document.getElementById('btn-theme');
  if (!b) return;
  b.addEventListener('click', function () {
    var r = document.documentElement, t = r.dataset.theme === 'dark' ? 'light' : 'dark';
    r.dataset.theme = t;
    try { localStorage.setItem('fleet-ids.theme', t); } catch (e) { /* ignore */ }
  });
});
