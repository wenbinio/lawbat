(function(){
'use strict';
const $=id=>document.getElementById(id);
let file=null, caps=null, review=null, page=1, accepted=new Set(), reviewed=new Set(), busy=false;
let generation=0, pageGeneration=0;
function notice(message,error=false){$('workspaceNotice').textContent=message;$('workspaceNotice').className='notice'+(error?' error':'');}
function buttons(){
 for(const el of document.querySelectorAll('#workspaceFile,#workspaceTerms,#builtinsOn,#visualAll,#workspacePacks input'))el.disabled=busy;
 $('scanDocument').disabled=busy||!file||!caps;
 $('prepareDocument').disabled=busy||!review||!accepted.size||reviewed.size!==review.pages.length;
 for(const id of ['previousPage','nextPage','pageNumber','reviewedPage','selectPage','clearPage'])$(id).disabled=busy||!review;
 $('reviewProgress').textContent=reviewed.size+' / '+(review?review.pages.length:0)+' pages reviewed · '+accepted.size+' selected';
}
async function invalidate(){
 generation++;pageGeneration++;
 if(review){const old=review.review_id;review=null;await LB.post('/api/redaction/discard-review',{review_id:old});}
 accepted.clear();reviewed.clear();$('workspaceFindings').replaceChildren();$('sourceImage').style.display='none';$('sourcePlaceholder').style.display='block';$('reviewedPage').checked=false;buttons();
}
$('workspaceFile').addEventListener('change',async()=>{await invalidate();file=$('workspaceFile').files[0]||null;$('workspaceFilename').textContent=file?file.name:'No document selected';$('scanState').textContent=file?'Ready to scan.':'Choose a PDF to begin.';buttons();});
for(const id of ['workspaceTerms','builtinsOn','visualAll'])$(id).addEventListener('input',()=>{if(review){invalidate();notice('Detection settings changed. The old review was invalidated; scan again.');}});
function options(){const o={terms:$('workspaceTerms').value.split(/\r?\n/).map(s=>s.trim()).filter(Boolean)};const locales=[...$('workspacePacks').querySelectorAll('input:checked')].map(x=>x.value);if(locales.length)o.locales=locales;if(!$('builtinsOn').checked)o.disable_builtins=caps.disable_builtins;return o;}
function encode(bytes){let s='';for(let i=0;i<bytes.length;i+=32768)s+=String.fromCharCode(...bytes.subarray(i,i+32768));return btoa(s);}
$('scanDocument').addEventListener('click',async()=>{
 if(busy||!file)return;
 await invalidate();const run=generation;busy=true;buttons();$('scanState').textContent='Scanning native text and visual content locally…';
 try{
  const r=await LB.post('/api/redaction/document-scan',{filename:file.name,data_b64:encode(new Uint8Array(await file.arrayBuffer())),options:options(),visual_all:$('visualAll').checked});
  if(run!==generation)return;
  if(!r.ok)throw Error(r.data.error||'Scan failed');review=r.data;page=1;accepted.clear();reviewed.clear();
  $('pageTotal').textContent='/ '+review.pages.length;$('pageNumber').max=review.pages.length;
  $('scanState').textContent=review.candidates.length+' findings across '+review.pages.length+' pages. Nothing changed on disk.';
  notice(review.notice+' '+review.limitations.join(' '));$('stepReview').style.color='#075e55';await renderPage();
 }catch(e){notice(e.message,true);$('scanState').textContent='Scan did not complete.';}finally{busy=false;buttons();}
});
async function renderPage(){
 if(!review)return;const run=++pageGeneration,current=review.review_id;
 $('pageNumber').value=page;$('reviewedPage').checked=reviewed.has(page);
 const metadata=review.pages[page-1];$('pageCoverage').textContent='Page '+page+' · '+metadata.processing+' · OCR: '+metadata.ocr;
 const list=$('workspaceFindings');list.replaceChildren();const findings=review.candidates.filter(c=>c.page===page);$('findingCount').textContent=findings.length;
 for(const c of findings){const row=document.createElement('label');row.className='finding';const box=document.createElement('input');box.type='checkbox';box.checked=accepted.has(c.id);box.dataset.id=c.id;box.addEventListener('change',()=>{if(box.checked)accepted.add(c.id);else accepted.delete(c.id);buttons();});row.appendChild(box);const value=document.createElement('b');value.textContent=c.value;row.appendChild(value);const sub=document.createElement('span');sub.textContent=c.surface+' · '+c.recognizer;row.appendChild(sub);list.appendChild(row);}
 if(!findings.length){const p=document.createElement('p');p.className='muted';p.textContent='No findings were detected on this page. This does not replace manual review.';list.appendChild(p);}
 const r=await LB.post('/api/redaction/document-page',{review_id:current,page});
 if(run!==pageGeneration||!review||current!==review.review_id)return;
 if(r.ok){$('sourceImage').src='data:image/png;base64,'+r.data.image;$('sourceImage').style.display='block';$('sourcePlaceholder').style.display='none';}else notice(r.data.error||'Page preview failed',true);
 buttons();
}
$('previousPage').onclick=()=>{if(review&&page>1){page--;renderPage();}};$('nextPage').onclick=()=>{if(review&&page<review.pages.length){page++;renderPage();}};$('pageNumber').onchange=()=>{if(review){page=Math.max(1,Math.min(review.pages.length,Number($('pageNumber').value)||1));renderPage();}};
$('reviewedPage').onchange=()=>{if($('reviewedPage').checked)reviewed.add(page);else reviewed.delete(page);buttons();};
$('selectPage').onclick=()=>{review.candidates.filter(c=>c.page===page).forEach(c=>accepted.add(c.id));renderPage();};$('clearPage').onclick=()=>{review.candidates.filter(c=>c.page===page).forEach(c=>accepted.delete(c.id));renderPage();};
$('prepareDocument').onclick=async()=>{
 if(!review||busy)return;busy=true;buttons();$('prepareState').textContent='Preparing privately, checking exact output bytes and image content…';
 try{
  const r=await LB.post('/api/redaction/document-prepare',{review_id:review.review_id,accepted:[...accepted],reviewed_pages:[...reviewed]});
  if(!r.ok)throw Error(r.data.error||'Preparation failed');$('stepPrepare').style.color='#075e55';
  const released=await presentPreparedRelease(r.data);
  if(!released.ok){$('prepareState').textContent='No copy released. Return to review or prepare again.';return;}
  $('stepRelease').style.color='#e0a94f';$('prepareState').textContent='Document and reports released as one package. The source remains unchanged.';
  const receipt=$('releaseReceipt');receipt.replaceChildren();const h=document.createElement('h2');h.textContent='Released with recorded review limitations';receipt.appendChild(h);const p=document.createElement('p');p.textContent='The document, verification reports and release receipt were published together. This is not a certification of anonymity.';receipt.appendChild(p);const code=document.createElement('code');code.textContent=released.data.filename;receipt.appendChild(code);const b=document.createElement('button');b.textContent='Open released package';b.style.marginLeft='14px';b.onclick=()=>LB.post('/api/redaction/open-export',{filename:released.data.filename});receipt.appendChild(b);receipt.style.display='block';receipt.scrollIntoView({behavior:'smooth',block:'center'});
 }catch(e){notice(e.message,true);$('prepareState').textContent='No completed release was created.';}finally{busy=false;buttons();}
};
LB.get('/api/redaction/capabilities').then(r=>{
 if(!r.ok)throw Error(r.data.error||'Engine unavailable');caps=r.data;$('engineStatus').textContent='Local engine ready · no cloud calls';
 for(const locale of caps.locales){const label=document.createElement('label'),box=document.createElement('input');box.type='checkbox';box.value=locale;box.checked=locale==='sg';box.onchange=()=>{if(review){invalidate();notice('Detection settings changed. Scan again.');}};label.appendChild(box);label.appendChild(document.createTextNode(' '+locale.toUpperCase()));$('workspacePacks').appendChild(label);}buttons();
}).catch(e=>{$('engineStatus').textContent='Engine unavailable';notice(e.message,true);});
async function loadHarbourPdf(){
  const r = await LB.get('/api/demo/sample');
  if(!r.ok || !r.data || !r.data.data_b64) return;
  const bin = atob(r.data.data_b64);
  const bytes = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i);
  const f = new File([bytes], r.data.filename || 'harbour-lane-sample.pdf', {type:'application/pdf'});
  const input = $('workspaceFile');
  const dt = new DataTransfer();
  dt.items.add(f);
  input.files = dt.files;
  input.dispatchEvent(new Event('change'));
  if(r.data.text) $('workspaceTerms').value = 'Harbour Lane\nPriya Shah\nAlex Rivera';
}
const harbourWs = $('harbourWs');
if(harbourWs) harbourWs.addEventListener('click', ()=>loadHarbourPdf().catch(()=>notice('Could not load the sample.', true)));
if(document.body && document.body.getAttribute('data-demo')==='1') loadHarbourPdf().catch(()=>{});
})();
