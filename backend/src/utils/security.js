const crypto=require('node:crypto');
function randomToken(){return crypto.randomBytes(32).toString('base64url')}
function hashToken(v){return crypto.createHash('sha256').update(String(v)).digest('hex')}
function hashPassword(password){const salt=crypto.randomBytes(16);const key=crypto.scryptSync(String(password),salt,64,{N:16384,r:8,p:1});return `scrypt$${salt.toString('base64url')}$${key.toString('base64url')}`}
function verifyPassword(password,stored){try{const [,s,k]=String(stored).split('$');const salt=Buffer.from(s,'base64url');const expected=Buffer.from(k,'base64url');const actual=crypto.scryptSync(String(password),salt,expected.length,{N:16384,r:8,p:1});return crypto.timingSafeEqual(actual,expected)}catch{return false}}
function cleanText(v,max=120){return String(v??'').trim().replace(/[<>]/g,'').slice(0,max)}
function normalizePhone(v){return String(v??'').replace(/[^0-9+]/g,'').slice(0,20)}
function sign(payload,secret,days=7){const b64=v=>Buffer.from(JSON.stringify(v)).toString('base64url');const h=b64({alg:'HS256',typ:'JWT'});const body=b64({...payload,iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+days*86400});const sig=crypto.createHmac('sha256',secret).update(`${h}.${body}`).digest('base64url');return `${h}.${body}.${sig}`}
function verify(token,secret){const [h,b,s]=String(token||'').split('.');if(!h||!b||!s)throw Error('Invalid token');const expected=crypto.createHmac('sha256',secret).update(`${h}.${b}`).digest('base64url');if(s.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(expected)))throw Error('Invalid token');const p=JSON.parse(Buffer.from(b,'base64url'));if(!p.exp||p.exp<Math.floor(Date.now()/1000))throw Error('Expired token');return p}
module.exports={randomToken,hashToken,hashPassword,verifyPassword,cleanText,normalizePhone,sign,verify};
