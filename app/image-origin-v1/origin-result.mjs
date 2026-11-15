// Conservative local prototype. No approved signer trust policy is configured.
const own = (v,k) => Object.prototype.hasOwnProperty.call(v,k);
const object = v => !!v && typeof v==='object' && !Array.isArray(v);
const base = (status,present=null) => ({status,manifest_present:present,
  signature_verified:false,binding_verified:null,signer_trusted:null,ai_status:'unknown'});
const codes = (list,bucket) => {
  if (!Array.isArray(list) || list.length>1000 || list.some(x=>!object(x)||typeof x.code!=='string'||!x.code.length||x.code.length>128||
      (x.success!=null && typeof x.success!=='boolean') ||
      (bucket==='success' && x.success===false) || (bucket==='failure' && x.success===true))) return null;
  return list.map(x=>x.code);
};

export function normalizeOrigin(result) {
  if (!object(result) || result.ok!==true || !own(result,'store')) return base('unavailable');
  if (result.store===null) return base('none',false);
  const s=result.store;
  if (!object(s) || !own(s,'active_manifest') || typeof s.active_manifest!=='string' || !s.active_manifest.trim() || s.active_manifest.length>512 ||
      !object(s.manifests) || !own(s.manifests,s.active_manifest) || !object(s.manifests[s.active_manifest])) return base('unverified');
  const active=s.validation_results?.activeManifest;
  if (!object(active)) return base('unverified',true);
  const success=codes(active.success,'success'), failure=codes(active.failure,'failure'), informational=codes(active.informational,'informational');
  if (!success || !failure || !informational) return base('unverified',true);
  if (s.validation_state==='Invalid') {
    const r=base('invalid',true);
    if (failure.includes('assertion.dataHash.mismatch')) r.binding_verified=false;
    return r;
  }
  // Flat legacy status output must not contradict the active summary. Unknown
  // flat codes are incomplete here, rather than silently ignored as successes.
  const legacy=s.validation_status==null?[]:codes(s.validation_status,'legacy');
  if (!legacy || legacy.some(c=>c!=='signingCredential.untrusted')) return base('unverified',true);
  // For this initial JPEG/PNG slice, require explicit claim signature AND data
  // binding successes. A valid COSE signature alone survives pixel tampering.
  if (!['Valid','Trusted'].includes(s.validation_state) ||
      !success.includes('claimSignature.validated') || !success.includes('assertion.dataHash.match') ||
      failure.some(c=>c!=='signingCredential.untrusted')) return base('unverified',true);
  return {...base('valid_untrusted',true),signature_verified:true,binding_verified:true,
    signer_trusted:failure.includes('signingCredential.untrusted')?false:null};
}

export const ORIGIN_COPY = Object.freeze({
  valid_untrusted: {heading:'Record matches this file; signer unverified',body:'The record’s signature and connection to this file passed this check. Bevins has not established that the signer is trusted.'},
  invalid: {heading:'Origin record did not pass validation',body:'The record or its link to this file failed validation. This result alone does not establish whether the image is fake or why the check failed.'},
  none: {heading:'No embedded origin record found',body:'Many everyday photos have no Content Credentials. This does not tell us whether the picture is real, edited, or AI-generated.'},
  unverified: {heading:'Origin information could not be fully verified',body:'Bevins could not complete a supported signature and file-binding check. Treat the origin as unknown.'},
  unavailable: {heading:'Image origin check unavailable',body:'The check could not read or finish checking this file. Whether an origin record is present is unknown.'}
});
export const ORIGIN_LIMIT='This does not confirm that the picture is true, who sent it, that a request is safe, or whether an emergency is real. AI generation is not determined by this check.';
export const ORIGIN_ACTION='For an urgent request, pause before sending money or codes. Call the person using a number you already know, or contact another trusted family member. If someone may be in immediate danger, contact local emergency services yourself.';
