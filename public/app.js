function togglePass(id){ const el = document.getElementById(id); if(!el) return; el.type = el.type === 'password' ? 'text' : 'password'; }
