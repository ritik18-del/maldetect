const form = document.getElementById('scanForm');
const fileInput = document.getElementById('fileInput');
const algoSelect = document.getElementById('algo');
const result = document.getElementById('result');
const resultContent = document.getElementById('resultContent');
const errorBox = document.getElementById('error');
const progressEl = document.getElementById('progress');
const progressBar = progressEl?.querySelector('div');
const dropzone = document.getElementById('dropzone');
const probbar = document.getElementById('probbar');
const probfill = probbar?.querySelector('div');
const historyEl = document.getElementById('history');
const resultIcon = document.getElementById('resultIcon');

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  errorBox.hidden = true;
  result.hidden = true;
  setProgress(0);

  if (!fileInput.files || fileInput.files.length === 0) {
    showError('Please choose a file.');
    return;
  }

  const data = new FormData();
  data.append('file', fileInput.files[0]);
  if (algoSelect && algoSelect.value) data.append('algo', algoSelect.value);

  try {
    setProgress(20);
    const res = await fetch('/api/scan', { method: 'POST', body: data });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || 'Scan failed');
    setProgress(90);
    showResult(json, fileInput.files[0]);
    setProgress(100);
  } catch (err) {
    showError(err.message || String(err));
    setProgress(0);
  }
});

function showResult(json, file) {
  const { label, confidence_malicious, model, stats } = json;
  const pct = (confidence_malicious * 100).toFixed(2);
  resultContent.innerHTML = `
    <p><strong>Prediction:</strong> ${label.toUpperCase()}</p>
    <p><strong>Confidence (malicious):</strong> ${pct}%</p>
    <p><strong>Model:</strong> ${model?.name || 'N/A'} (${model?.version || 'v1'})</p>
    ${stats ? `<p><strong>SHA-256:</strong> ${stats.sha256}</p>` : ''}
    ${stats ? `<p><strong>Size:</strong> ${formatBytes(stats.file_size)}</p>` : ''}
    ${stats ? `<p><strong>Entropy:</strong> ${stats.entropy?.toFixed?.(2)}</p>` : ''}
  `;
  result.hidden = false;

  // probability bar
  const num = Number(pct);
  if (probbar && probfill) {
    probfill.style.width = `${num}%`;
    probbar.classList.remove('red','yellow');
    if (num >= 60) probbar.classList.add('red');
    else if (num >= 30) probbar.classList.add('yellow');
  }

  // history
  appendHistory({
    name: file?.name || 'file',
    algo: model?.algo || 'auto',
    label: label.toUpperCase(),
    pct,
    time: new Date().toLocaleTimeString()
  });

  // status icon
  if (resultIcon) {
    resultIcon.innerHTML = label === 'malicious'
      ? '<img src="/static/icons/status-malicious.svg" alt="malicious" />'
      : '<img src="/static/icons/status-benign.svg" alt="benign" />';
  }
}

function showError(msg) {
  errorBox.textContent = msg;
  errorBox.hidden = false;
}

function setProgress(val){
  if(!progressEl || !progressBar) return;
  progressEl.hidden = val <= 0 || val >= 100 ? false : false;
  progressBar.style.width = `${val}%`;
  if(val === 0 || val === 100) setTimeout(()=>{ progressEl.hidden = true; }, 400);
}

// drag & drop
if (dropzone) {
  ;['dragenter','dragover'].forEach(evt => dropzone.addEventListener(evt, (e)=>{ e.preventDefault(); dropzone.style.background='#0b1220'; }));
  ;['dragleave','drop'].forEach(evt => dropzone.addEventListener(evt, (e)=>{ e.preventDefault(); dropzone.style.background='transparent'; }));
  dropzone.addEventListener('drop', (e)=>{
    const files = e.dataTransfer?.files;
    if (files && files.length) fileInput.files = files;
  });
}

function appendHistory(item){
  if(!historyEl) return;
  const el = document.createElement('div');
  el.className = 'item';
  const icon = pickFileIcon(item.name);
  el.innerHTML = `<span><img src="${icon}" alt="file" style="width:16px;height:16px;vertical-align:-3px;margin-right:6px;"/>${item.time} - ${escapeHtml(item.name)} [${item.algo}]</span><span>${item.label} (${item.pct}%)</span>`;
  historyEl.prepend(el);
}

function escapeHtml(s){ return String(s).replace(/[&<>"]+/g, c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"}[c])); }
function formatBytes(b){ try{const n=Number(b)||0; if(n<1024) return `${n} B`; const u=['KB','MB','GB','TB']; let i=-1, v=n; do{ v/=1024; i++; } while(v>=1024&&i<u.length-1); return `${v.toFixed(2)} ${u[i]}`;}catch{ return `${b}`; } }

function pickFileIcon(name){
  const n = String(name).toLowerCase();
  if(n.endsWith('.exe')) return '/static/icons/file-exe.svg';
  if(n.endsWith('.pdf')) return '/static/icons/file-pdf.svg';
  return '/static/icons/file-generic.svg';
}


