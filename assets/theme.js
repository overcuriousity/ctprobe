// Runs before first paint, so a stored choice never flashes the other theme.
(function () {
  var html = document.documentElement;
  try {
    var theme = localStorage.getItem('theme');
    if (theme === 'light' || theme === 'dark') html.dataset.theme = theme;
    if (localStorage.getItem('density') === 'compact') html.dataset.density = 'compact';
  } catch (e) {
    /* storage blocked: keep the defaults */
  }
})();
