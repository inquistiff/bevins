export const MAX_IMAGE_BYTES=15*1024*1024;
export const CHECK_TIMEOUT_MS=12000;
const reasons=new Set(['unsupported_format','oversize','cancelled','busy','timeout','reader_unavailable','asset_unavailable','invalid_result']);
const statuses=new Set(['valid_untrusted','invalid','none','unverified','unavailable']);
const keys=['status','manifest_present','signature_verified','binding_verified','signer_trusted','ai_status','reason'].sort();

export function unavailable(reason='reader_unavailable') {
  return {status:'unavailable',manifest_present:null,signature_verified:false,
    binding_verified:null,signer_trusted:null,ai_status:'unknown',reason:reasons.has(reason)?reason:'reader_unavailable'};
}

// Copy only a fixed small schema. A worker error, arbitrary property, inconsistent
// flag, signer claim or raw manifest can never cross into display/history.
export function validateSummary(value) {
  if (!value || typeof value!=='object' || Array.isArray(value) ||
      Object.keys(value).sort().join('|')!==keys.join('|') || !statuses.has(value.status) ||
      value.ai_status!=='unknown' || value.signer_trusted===true) return unavailable('invalid_result');
  const {status,manifest_present:p,signature_verified:s,binding_verified:b,signer_trusted:t,reason:r}=value;
  if ((r!==null && !reasons.has(r)) || (status!=='unavailable' && r!==null)) return unavailable('invalid_result');
  const good=status==='valid_untrusted' ? p===true&&s===true&&b===true&&(t===false||t===null) :
    status==='invalid' ? p===true&&s===false&&(b===false||b===null)&&t===null :
    status==='none' ? p===false&&s===false&&b===null&&t===null :
    status==='unverified' ? (p===true||p===null)&&s===false&&b===null&&t===null :
    p===null&&s===false&&b===null&&t===null&&reasons.has(r);
  if (!good) return unavailable('invalid_result');
  return {status,manifest_present:p,signature_verified:s,binding_verified:b,signer_trusted:t,ai_status:'unknown',reason:r};
}
