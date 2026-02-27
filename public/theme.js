// Apply theme instantly before /api/me resolves
(function () {
  if (localStorage.getItem('theme_pending') === 'dark') {
    document.body.classList.add('dark-mode');
  }
})();

// Sync with user-scoped key + wire up toggle if present
document.addEventListener('DOMContentLoaded', () => {
  const toggleSwitch = document.getElementById('themeToggle');

  if (toggleSwitch) {
    toggleSwitch.checked = document.body.classList.contains('dark-mode');
  }

  fetch('/api/me')
    .then(r => r.json())
    .then(d => {
      const userId = d.userId;
      if (!userId) return;

      const themeKey = `theme_${userId}`;

      if (!localStorage.getItem(themeKey) && localStorage.getItem('theme_pending')) {
        localStorage.setItem(themeKey, localStorage.getItem('theme_pending'));
      }

      const isDark = localStorage.getItem(themeKey) === 'dark';
      document.body.classList.toggle('dark-mode', isDark);
      localStorage.setItem('theme_pending', isDark ? 'dark' : 'light');

      if (toggleSwitch) {
        toggleSwitch.checked = isDark;

        toggleSwitch.addEventListener('change', () => {
          const isDark = toggleSwitch.checked;
          document.body.classList.toggle('dark-mode', isDark);
          localStorage.setItem(themeKey, isDark ? 'dark' : 'light');
          localStorage.setItem('theme_pending', isDark ? 'dark' : 'light');
        });
      }
    })
    .catch(() => {
      if (localStorage.getItem('theme_pending') === 'dark') {
        document.body.classList.add('dark-mode');
      }
    });
});