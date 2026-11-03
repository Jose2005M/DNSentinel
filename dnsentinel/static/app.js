const $ = s => document.querySelector(s);
let state={rules:[],logs:[]},kind='block',editing=null,toastTimer,currentUser=null;
const esc = v => String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function toast(message){$('#toast').textContent=message;$('#toast').hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('#toast').hidden=true,3500);}
function stat(label,value,note,symbol,color=''){return `<div class="stat"><div class="stat-label">${label}</div><div class="stat-value">${value}</div><div class="stat-note">${note}</div><span class="stat-icon ${color}">${symbol}</span></div>`;}
function badge(active){return `<span class="pill ${active?'active':'inactive'}"><i></i>${active?'Activo':'Inactivo'}</span>`;}
function decisionBadge(value){return `<span class="pill ${value==='blocked'?'blocked':'active'}"><i></i>${value==='blocked'?'Bloqueada':'Permitida'}</span>`;}
function renderRules(){const blocked=state.rules.filter(r=>r.kind==='block'),allowed=state.rules.filter(r=>r.kind==='allow');$('#nav-count').textContent=state.rules.length;$('#block-count').textContent=blocked.length;$('#allow-count').textContent=allowed.length;$('#rule-stats').innerHTML=stat('Dominios en bloqueo',blocked.length,`${blocked.filter(r=>r.active).length} reglas activas`,'⊘','red')+stat('Excepciones permitidas',allowed.length,'Tienen prioridad sobre el bloqueo','✓','green')+stat('Reglas activas',state.rules.filter(r=>r.active).length,`${state.rules.filter(r=>!r.active).length} reglas inactivas`,'≡');
const q=$('#rule-search').value.toLowerCase(),filter=$('#status-filter').value;
const list=state.rules.filter(r=>r.kind===kind&&(!q||(r.domain+' '+r.note).toLowerCase().includes(q))&&(filter==='all'||r.active===(filter==='active')));
$('#rules-body').innerHTML=list.length?list.map(r=>`<tr><td><div class="domain-cell"><span class="domain-icon">◎</span><div><span class="domain-name">${esc(r.domain)}</span><small>${esc(r.note||'Sin descripción')}</small></div></div></td><td><span class="match">${r.subdomains?'Dominio y subdominios':'Solo dominio exacto'}</span></td><td>${badge(r.active)}</td><td><div class="row-actions" ${currentUser?.role!=='admin'?'hidden':''}><button class="text-action" data-action="edit" data-id="${esc(r.id)}" aria-label="Editar ${esc(r.domain)}">Editar</button><button class="text-action" data-action="toggle" data-id="${esc(r.id)}" aria-label="${r.active?'Desactivar':'Activar'} ${esc(r.domain)}">${r.active?'Desactivar':'Activar'}</button><button class="text-action" data-action="delete" data-id="${esc(r.id)}" aria-label="Eliminar ${esc(r.domain)}">×</button></div></td></tr>`).join(''):'<tr><td colspan="4" class="empty">No hay dominios que coincidan. Agrega una regla o ajusta los filtros.</td></tr>';
$('#results-count').textContent=`${list.length} ${list.length===1?'dominio':'dominios'} en esta vista`;
document.querySelectorAll('[data-kind]').forEach(b=>b.setAttribute('aria-selected',String(b.dataset.kind===kind)));
}
function formatTime(t){return new Date(t).toLocaleString('es-CO',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit',second:'2-digit'});}
function renderLogs(){const q=$('#log-search').value.toLowerCase(),filter=$('#log-filter').value;const list=state.logs.filter(l=>l.domain.includes(q)&&(filter==='all'||filter===l.decision));$('#logs-body').innerHTML=list.length?list.map(l=>`<tr><td>${esc(formatTime(l.time))}</td><td><span class="domain-name">${esc(l.domain)}</span><small class="muted" style="margin:4px 0 0;font-size:10px">${esc(l.type)} · ${esc(l.transport)} simulado</small></td><td>${decisionBadge(l.decision)}</td><td class="match">${esc(l.reason)}</td></tr>`).join(''):'<tr><td colspan="4" class="empty">No hay consultas en esta vista. <a href="#simulador">Prueba un dominio en el simulador.</a></td></tr>';$('#log-count').textContent=`${list.length} consultas`;$('#export-logs').disabled=state.logs.length===0;}
function renderOverview(){const n=state.logs.length,b=state.logs.filter(l=>l.decision==='blocked').length,a=n-b;$('#overview-stats').innerHTML=stat('Consultas simuladas',n,'Guardadas en SQLite (últimas 200)','⌁')+stat('Consultas bloqueadas',b,'Coincidencia con una regla activa','⊘','red')+stat('Consultas permitidas',a,'Excepción o sin regla de bloqueo','✓','green');$('#distribution').innerHTML=`<div class="dist-number">${n?Math.round(b/n*100):0}<span style="font-size:22px;color:#82958f">%</span></div><div class="dist-label">${n?'de las consultas simuladas fueron bloqueadas':'Ejecuta una consulta para ver resultados'}</div><div class="dist-bar"><span style="width:${n?a/n*100:0}%"></span><span style="width:${n?b/n*100:0}%"></span></div><div class="dist-legend"><span>Permitidas · ${a}</span><span>Bloqueadas · ${b}</span></div>`;$('#recent-activity').innerHTML=state.logs.length?state.logs.slice(0,4).map(l=>`<div class="activity-row"><span class="domain-name">${esc(l.domain)}</span>${decisionBadge(l.decision)}<time>${esc(formatTime(l.time))}</time></div>`).join(''):'<div class="empty">Tu actividad aparecerá aquí. <a href="#simulador">Simular primera consulta →</a></div>';}
function render(){renderRules();renderLogs();renderOverview();}
function route(){let page=location.hash.slice(1)||'reglas';if(!['reglas','resumen','actividad','simulador','auditoria'].includes(page))page='reglas';document.querySelectorAll('.page').forEach(s=>s.hidden=s.id!=='page-'+page);document.querySelectorAll('[data-page]').forEach(a=>{a.classList.toggle('active',a.dataset.page===page);if(a.dataset.page===page)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');});$('#breadcrumb').textContent={reglas:'Control de dominios',resumen:'Resumen',actividad:'Registro de consultas',simulador:'Probar una consulta',auditoria:'Auditoría de seguridad'}[page];render();}
function openRule(id){editing=id||null;const r=state.rules.find(r=>r.id===id);$('#rule-form').reset();$('#rule-error').textContent='';$('#dialog-title').textContent=r?'Editar dominio':'Agregar dominio';$('#domain-input').value=r?.domain||'';$('#kind-input').value=r?.kind||kind;$('#note-input').value=r?.note||'';$('#subdomain-input').checked=r?.subdomains||false;$('#active-input').checked=r?.active??true;$('#rule-dialog').showModal();$('#domain-input').focus();}
$('#add-rule').addEventListener('click',()=>openRule());$('#close-dialog').addEventListener('click',()=>$('#rule-dialog').close());$('#cancel-dialog').addEventListener('click',()=>$('#rule-dialog').close());
function rulePayload(rule) {
  return Object.fromEntries(['domain','kind','note','subdomains','active'].map(key => [key,rule[key]]));
}
function showConnectionError(error) {
  let box = $('#connection-error');
  if (!box) { box = document.createElement('p'); box.id='connection-error'; box.setAttribute('role','alert'); document.querySelector('main').prepend(box); }
  box.textContent = error.message + ' Recarga la página para reintentar.';
}
async function refresh() {
  const [rules,events] = await Promise.all([api('/rules'),api('/events')]);
  state={rules:rules.rules,logs:events.logs};
  render();
  if(currentUser?.role==='admin')await refreshAudit();
}
async function refreshAudit() {
  const data=await api('/audit');
  $('#audit-body').innerHTML=data.audit.length?data.audit.map(a=>`<tr><td>${esc(formatTime(a.time))}</td><td>${esc(a.actor)}</td><td>${esc(a.action)}</td><td>${esc(a.result)}</td><td>${esc(a.detail)}</td></tr>`).join(''):'<tr><td colspan="5" class="empty">No hay eventos de seguridad registrados.</td></tr>';
}
$('#rule-form').addEventListener('submit',async e=>{
  e.preventDefault();
  const submit=e.submitter; if(submit)submit.disabled=true;
  try {
    const payload={domain:$('#domain-input').value,kind:$('#kind-input').value,note:$('#note-input').value,subdomains:$('#subdomain-input').checked,active:$('#active-input').checked};
    await api(editing?'/rules/'+editing:'/rules',{method:editing?'PUT':'POST',body:JSON.stringify(payload)});
    kind=payload.kind;$('#rule-search').value='';$('#status-filter').value='all';
    $('#rule-dialog').close();await refresh();toast('Regla guardada en el servidor.');
  } catch(error){$('#rule-error').textContent=error.message;toast(error.message);}
  finally{if(submit)submit.disabled=false;}
});
$('#rules-body').addEventListener('click',async e=>{
  const b=e.target.closest('[data-action]');if(!b)return;
  const rule=state.rules.find(r=>String(r.id)===b.dataset.id);if(!rule)return;
  if(b.dataset.action==='edit'){openRule(rule.id);return;}
  if(b.dataset.action==='delete'&&!confirm(`¿Eliminar la regla para ${rule.domain}?`))return;
  b.disabled=true;
  try{
    await api('/rules/'+rule.id,{method:b.dataset.action==='delete'?'DELETE':'PUT',...(b.dataset.action==='toggle'?{body:JSON.stringify({...rulePayload(rule),active:!rule.active})}:{})});
    await refresh();toast('Reglas actualizadas en el servidor.');
  }catch(error){toast(error.message);b.disabled=false;}
});
document.querySelectorAll('[data-kind]').forEach(b=>b.addEventListener('click',()=>{kind=b.dataset.kind;renderRules();}));
for(const id of ['rule-search','status-filter'])$('#'+id).addEventListener('input',renderRules);
for(const id of ['log-search','log-filter'])$('#'+id).addEventListener('input',renderLogs);
$('#sim-form').addEventListener('submit',async e=>{
  e.preventDefault();$('#sim-error').textContent='';const button=e.submitter;if(button)button.disabled=true;
  try{
    const data=await api('/simulate',{method:'POST',body:JSON.stringify({domain:$('#sim-domain').value,type:$('#sim-type').value,transport:$('#sim-transport').value})});
    const result=data.event,blocked=result.decision==='blocked';
    $('#sim-result').classList.toggle('blocked',blocked);
    $('#sim-result').innerHTML=`<div class="result-symbol">${blocked?'⊘':'✓'}</div><div class="decision">${blocked?'CONSULTA BLOQUEADA':'CONSULTA PERMITIDA'}</div><h2>${esc(result.domain)}</h2><p>${esc(result.reason)}</p><span class="pill ${blocked?'blocked':'active'}">${blocked?'Respuesta prevista: REFUSED':'Acción prevista: reenviar al DNS'}</span><p>Evaluación realizada en Python. No se ha enviado ninguna consulta DNS.</p>`;
    await refresh();
  }catch(error){$('#sim-error').textContent=error.message;}
  finally{if(button)button.disabled=false;}
});
document.querySelectorAll('[data-example]').forEach(b=>b.addEventListener('click',()=>{$('#sim-domain').value=b.dataset.example;$('#sim-domain').focus();}));
$('#export-logs').addEventListener('click',()=>{
  const cell=value=>'"'+String(value).replace(/"/g,'""')+'"';
  const rows=[['fecha','dominio','tipo','transporte_simulado','decision','motivo'],...state.logs.map(l=>[l.time,l.domain,l.type,l.transport,l.decision,l.reason])];
  const url=URL.createObjectURL(new Blob(['\uFEFF'+rows.map(r=>r.map(cell).join(',')).join('\r\n')],{type:'text/csv;charset=utf-8'}));
  const link=document.createElement('a');link.href=url;link.download='dnsentinel-consultas-simuladas.csv';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});
$('#logout').addEventListener('click',async()=>{try{await api('/logout',{method:'POST'});location.replace('/login');}catch(error){toast(error.message);}});
$('#refresh-audit').addEventListener('click',()=>refreshAudit().catch(error=>toast(error.message)));
window.addEventListener('hashchange',route);
async function start(){
  try{
    const session=await api('/session');if(!session.user){location.replace('/login');return;}
    currentUser=session.user;$('#account-name').textContent=currentUser.username;
    $('#account-role').textContent=currentUser.role==='admin'?'Administrador':'Solo lectura';
    $('#add-rule').hidden=currentUser.role!=='admin';$('#audit-nav').hidden=currentUser.role!=='admin';
    await refresh();route();
  }catch(error){showConnectionError(error);}
}
start();
