/* Private preparation/release boundary shared by every legacy export action. */
  var _postBeforeRelease = post;
  post = async function(url, payload){
    var response = await _postBeforeRelease(url, payload);
    if (!response.ok || !response.data || !response.data.prepared) return response;
    return presentPreparedRelease(response.data);
  };
  function presentPreparedRelease(prepared){
    return new Promise(function(resolve){
      var dialog = document.createElement('dialog');
      dialog.style.cssText = 'width:min(1080px,94vw);max-height:94vh;border:1px solid #ccd3dd;border-radius:16px;padding:24px;color:#172033;background:white;';
      var heading = document.createElement('h2');
      heading.textContent = 'Prepared — not yet released'; dialog.appendChild(heading);
      var intro = document.createElement('p');
      intro.textContent = 'The original is unchanged. This working draft is outside your exports folder. Inspect it before releasing a copy.';
      dialog.appendChild(intro);
      var status = document.createElement('strong');
      status.textContent = !prepared.release_allowed ? 'Release blocked — resolve the failures below.' : prepared.exception_required ? 'Manual exception required — checks are incomplete.' : 'No targeted residuals detected — manual inspection is still required.';
      dialog.appendChild(status);
      var reasons = document.createElement('div');
      reasons.style.cssText='max-height:180px;overflow:auto;padding:10px 0;font-size:14px;';
      (prepared.blocked_reasons || []).concat(prepared.limitations || []).forEach(function(text){
        var line = document.createElement('p');line.textContent=text;line.style.margin='4px 0';reasons.appendChild(line);
      }); dialog.appendChild(reasons);
      var caution = document.createElement('p');caution.textContent = 'An absence of findings is not proof of anonymity. Unknown identifiers and identifying context remain your responsibility.';dialog.appendChild(caution);
      var select = document.createElement('select');
      (prepared.files || []).forEach(function(file){var option=document.createElement('option');option.value=file.name;option.textContent=file.name;select.appendChild(option);});dialog.appendChild(select);
      var pageInput=document.createElement('input');pageInput.type='number';pageInput.min=1;pageInput.value=1;pageInput.style.width='70px';pageInput.setAttribute('aria-label','Preview page');dialog.appendChild(pageInput);
      var preview=document.createElement('div');preview.style.cssText='max-height:45vh;overflow:auto;margin:14px 0;background:#f4f6f9;border:1px solid #dbe0e8;';
      function button(label, action){var b=document.createElement('button');b.textContent=label;b.type='button';b.style.margin='6px';b.addEventListener('click',action);dialog.appendChild(b);return b;}
      async function inspect(report){
        try {
        var r=await _postBeforeRelease('/api/redaction/prepared-preview',{preparation_id:prepared.preparation_id,filename:select.value,page:Number(pageInput.value),report:report});
        preview.replaceChildren();
        if(!r.ok){preview.textContent=(r.data||{}).error || 'Preview unavailable';return;}
        if(r.data.image){var img=document.createElement('img');img.src='data:image/png;base64,'+r.data.image;img.alt='Actual prepared PDF page';img.style.width='100%';preview.appendChild(img);pageInput.max=r.data.pages;}
        else {var pre=document.createElement('pre');pre.style.cssText='white-space:pre-wrap;overflow-wrap:anywhere;padding:12px';pre.textContent=r.data.text;preview.appendChild(pre);}
        }catch(e){preview.textContent='Preview request failed. Nothing was released.';}
      }
      button('Inspect prepared copy',function(){inspect(false);});button('Read verification report',function(){inspect(true);});dialog.appendChild(preview);
      var checkLabel=document.createElement('label');var inspected=document.createElement('input');inspected.type='checkbox';checkLabel.appendChild(inspected);checkLabel.appendChild(document.createTextNode(' I have inspected the prepared output.'));dialog.appendChild(checkLabel);
      var exception=document.createElement('textarea');exception.placeholder='Record the specific manual-review exception; do not include confidential names.';exception.setAttribute('aria-label','Manual-review exception');exception.style.cssText='display:block;width:100%;min-height:65px;margin-top:10px;';exception.maxLength=2000;exception.hidden=!prepared.exception_required;dialog.appendChild(exception);
      if(prepared.has_key){var keyNote=document.createElement('p');keyNote.textContent='The re-identification key will be retained separately in local app data, never inside the released package.';dialog.appendChild(keyNote);}
      var error=document.createElement('p');error.setAttribute('role','alert');dialog.appendChild(error);
      var releaseButton=button('Release document and report',async function(){
        releaseButton.disabled=true;
        try {
        var r=await _postBeforeRelease('/api/redaction/release',{preparation_id:prepared.preparation_id,inspected:inspected.checked,exception_reason:exception.value});
        if(!r.ok){error.textContent=(r.data||{}).error || 'Release failed';refresh();return;}
        dialog.close();dialog.remove();resolve(r);
        } catch(e){error.textContent='Could not confirm release status. Check the exports folder before retrying.';refresh();}
      });
      function refresh(){releaseButton.disabled=!prepared.release_allowed || !inspected.checked || (prepared.exception_required && exception.value.trim().length<12);}
      inspected.addEventListener('change',refresh);exception.addEventListener('input',refresh);refresh();
      async function discard(){try{await _postBeforeRelease('/api/redaction/discard-prepared',{preparation_id:prepared.preparation_id});}catch(e){/* Expiring private job is not released. */}dialog.close();dialog.remove();resolve({ok:false,status:409,data:{error:'Preparation discarded. No copy was released.'}});}
      button('Discard and return to review',discard);dialog.addEventListener('cancel',function(event){event.preventDefault();discard();});
      document.body.appendChild(dialog);dialog.showModal();
    });
  }
