import { createClient } from "https://esm.sh/@supabase/supabase-js@2.57.0";
const cors = {"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"authorization, x-client-info, apikey, content-type","Access-Control-Allow-Methods":"POST, OPTIONS","Content-Type":"application/json"};
const json=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers:cors});
const enc=new TextEncoder();
const hex=(b:Uint8Array)=>[...b].map(x=>x.toString(16).padStart(2,"0")).join("");
async function sha(v:string){return hex(new Uint8Array(await crypto.subtle.digest("SHA-256",enc.encode(v))))}
async function hasActiveSlot(db:any,roomId:string,deviceHash:string){
 if(!deviceHash)return false;
 const cutoff=new Date(Date.now()-120*1000).toISOString();
 const {data,error}=await db.from("chat_pin_connections").select("device_hash").eq("room_id",roomId).eq("device_hash",deviceHash).gte("last_seen_at",cutoff).maybeSingle();
 if(error)throw error;
 return !!data;
}
function roomSecret(){const b=crypto.getRandomValues(new Uint8Array(32));let s="";for(const x of b)s+=String.fromCharCode(x);return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}
function pinCode(){return String(crypto.getRandomValues(new Uint32Array(1))[0]%900000+100000)}
Deno.serve(async(req)=>{
 if(req.method==="OPTIONS")return new Response("ok",{headers:cors});
 if(req.method!=="POST")return json({error:"POST required"},405);
 try{
  const url=Deno.env.get("SUPABASE_URL"),key=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if(!url||!key)return json({error:"Server configuration missing"},500);
  const db=createClient(url,key,{auth:{persistSession:false,autoRefreshToken:false}});
  const body=await req.json(); const action=body?.action;
  const deviceId=typeof body?.deviceId==="string"&&/^[A-Za-z0-9-]{16,80}$/.test(body.deviceId)?body.deviceId:"";
  const deviceHash=deviceId?await sha("pc-device-v1:"+deviceId):"";
  const ip=req.headers.get("cf-connecting-ip")||req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()||"unknown";
  const ipHash=await sha("pc-ip-v1:"+ip),since=new Date(Date.now()-15*60*1000).toISOString(),pinThrottleCutover="2026-11-17T14:13:00.000Z";
  if((action==="create"||action==="join")&&!deviceHash)return json({error:"This device could not be identified. Refresh and retry."},400);
  if(action==="create"||action==="join"){
   const {count:ipCount,error:ipErr}=await db.from("chat_pin_attempts").select("*",{count:"exact",head:true}).eq("ip_hash",ipHash).gte("attempted_at",since);
   if(ipErr)throw ipErr;
   if((ipCount||0)>=20)return json({error:"Too many attempts from this connection. Try again in 15 minutes."},429);
  }
  if(action==="create"){
   const requestedPin=String(body?.pin||"");
   const customPin=requestedPin.length>0;
   if(customPin&&!/^\\d{6}$/.test(requestedPin))return json({error:"Choose exactly 6 digits for your personal PIN."},400);
   for(let n=0;n<(customPin?1:20);n++){
    const pin=customPin?requestedPin:pinCode(),pinHash=await sha("pc-pin-v1:"+pin),roomCode=roomSecret();
    const {data:created,error}=await db.from("chat_pin_rooms").insert({pin_hash:pinHash,room_code:roomCode,last_activity_at:new Date().toISOString()}).select("id").single();
    if(!error){
     const {data:claimed,error:claimErr}=await db.rpc("private_chat_claim_slot",{p_room_id:created.id,p_device_hash:deviceHash});
     if(claimErr)throw claimErr;
     if(!claimed){await db.from("chat_pin_rooms").delete().eq("id",created.id);return json({error:"Could not reserve a connection slot. Please retry."},503);}
     const {error:attemptErr}=await db.from("chat_pin_attempts").insert({ip_hash:ipHash,pin_hash:pinHash});
     if(attemptErr)throw attemptErr;
     return json({pin,roomCode});
    }
    if(error.code!=="23505")throw error;
    if(customPin)return json({error:"That PIN is already in use. Choose a different 6-digit PIN."},409);
   }
   return json({error:"Could not create a PIN. Retry."},503);
  }
  if(action==="join"){
   const pin=String(body?.pin||"");
   if(!/^\d{6}$/.test(pin))return json({error:"Enter a valid 6-digit PIN."},400);
   const pinHash=await sha("pc-pin-v1:"+pin);
   const {count:pinCount,error:pinErr}=await db.from("chat_pin_attempts").select("*",{count:"exact",head:true}).eq("pin_hash",pinHash).gte("attempted_at",since).gte("attempted_at",pinThrottleCutover);
   if(pinErr)throw pinErr;
   if((pinCount||0)>=10)return json({error:"Too many failed PIN attempts. Try again in 15 minutes."},429);
   const {data,error}=await db.from("chat_pin_rooms").select("id,room_code").eq("pin_hash",pinHash).maybeSingle();
   if(error)throw error;
   if(!data){
    const {error:attemptErr}=await db.from("chat_pin_attempts").insert({ip_hash:ipHash,pin_hash:pinHash});
    if(attemptErr)throw attemptErr;
    return json({error:"PIN not found. It may have expired or been deleted."},404);
   }
   const {data:claimed,error:claimErr}=await db.rpc("private_chat_claim_slot",{p_room_id:data.id,p_device_hash:deviceHash});
   if(claimErr)throw claimErr;
   if(!claimed)return json({error:"Two devices are already connected to this chat. Try again after one disconnects."},409);
   await db.from("chat_pin_delete_requests").delete().eq("room_id",data.id).eq("device_hash",deviceHash);
   const {error:touchErr}=await db.from("chat_pin_rooms").update({last_activity_at:new Date().toISOString()}).eq("id",data.id);
   if(touchErr)throw touchErr;
   return json({roomCode:data.room_code});
  }
  const roomCode=String(body?.roomCode||"");
  if(!/^[A-Za-z0-9_-]{32,100}$/.test(roomCode))return json({error:"Invalid room credential."},400);
  const {data:room,error:roomErr}=await db.from("chat_pin_rooms").select("id").eq("room_code",roomCode).maybeSingle();
  if(roomErr)throw roomErr;
  if(!room){if(action==="delete-status")return json({ok:true,deleted:true});return json({error:"Room not found. The PIN may have expired or been deleted."},404);}
  const now=new Date().toISOString();
  if(action==="delete-status"){
   if(!deviceHash)return json({error:"This device has no valid connection identity."},400);
   const {data:active,error:activeErr}=await db.from("chat_pin_connections").select("device_hash").eq("room_id",room.id).gte("last_seen_at",new Date(Date.now()-120*1000).toISOString());
   if(activeErr)throw activeErr;
   const activeHashes=(active||[]).map((x:any)=>x.device_hash);
   if(!activeHashes.includes(deviceHash))return json({error:"This device is not currently connected to this chat."},403);
   const cutoff=new Date(Date.now()-24*60*60*1000).toISOString();
   const {data,error}=await db.from("chat_pin_delete_requests").select("device_hash,requested_at").eq("room_id",room.id).gte("requested_at",cutoff);
   if(error)throw error;
   const rows=(data||[]).filter((x:any)=>activeHashes.includes(x.device_hash)),other=rows.find((x:any)=>x.device_hash!==deviceHash),mine=rows.some((x:any)=>x.device_hash===deviceHash);
   return json({ok:true,deleted:false,requestedByMe:mine,requestedByOther:!!other,otherRequestedAt:other?.requested_at||null});
  }
  if(action==="touch"){
   if(!deviceHash)return json({error:"This device has no valid connection identity."},400);
   const {data:claimed,error:claimErr}=await db.rpc("private_chat_claim_slot",{p_room_id:room.id,p_device_hash:deviceHash});
   if(claimErr)throw claimErr;
   if(!claimed)return json({error:"Your connection slot expired and both slots are now occupied. Reconnect after one device disconnects."},409);
   const {error}=await db.from("chat_pin_rooms").update({last_activity_at:now}).eq("id",room.id);if(error)throw error;return json({ok:true});
  }
  if(action==="disconnect"){
   if(!deviceHash)return json({error:"Invalid device identity."},400);
   const {error:releaseErr}=await db.rpc("private_chat_release_slot",{p_room_id:room.id,p_device_hash:deviceHash});
   if(releaseErr)throw releaseErr;
   await db.from("chat_pin_delete_requests").delete().eq("room_id",room.id).eq("device_hash",deviceHash);
   return json({ok:true});
  }
  if(action==="send"){
   if(!await hasActiveSlot(db,room.id,deviceHash))return json({error:"This device is not actively connected to this chat. Reconnect with the PIN."},403);
   const id=String(body?.id||""),sender=String(body?.sender||""),kind=String(body?.kind||"");
   const payload=body?.payload;
   if(!deviceId||sender!==deviceId||!/^[A-Za-z0-9-]{16,80}$/.test(id)||!/^[A-Za-z0-9-]{8,80}$/.test(sender)||!["text","photo","voice"].includes(kind)||!payload||typeof payload!=="object")return json({error:"Invalid message."},400);
   const size=enc.encode(JSON.stringify(payload)).length;
   if(size>350000)return json({error:"Encrypted message is too large."},413);
   const expiresAt=new Date(Date.now()+24*60*60*1000).toISOString();
   const {error}=await db.from("chat_messages").upsert({room_id:room.id,message_id:id,sender_id:sender,kind,payload,expires_at:expiresAt},{onConflict:"room_id,message_id",ignoreDuplicates:true});
   if(error)throw error;
   await db.from("chat_pin_rooms").update({last_activity_at:now}).eq("id",room.id);
   return json({ok:true,expiresAt});
  }
  if(action==="fetch"){
   if(!await hasActiveSlot(db,room.id,deviceHash))return json({error:"This device is not actively connected to this chat. Reconnect with the PIN."},403);
   const {data,error}=await db.from("chat_messages").select("message_id,sender_id,kind,payload,created_at,delivered_at,seen_at").eq("room_id",room.id).gt("expires_at",now).order("created_at",{ascending:true}).limit(500);
   if(error)throw error;
   await db.from("chat_pin_rooms").update({last_activity_at:now}).eq("id",room.id);
   return json({messages:data||[]});
  }
  if(action==="ack"){
   if(!await hasActiveSlot(db,room.id,deviceHash))return json({error:"This device is not actively connected to this chat. Reconnect with the PIN."},403);
   const status=String(body?.status||""),ids=Array.isArray(body?.ids)?body.ids.filter((x:unknown)=>typeof x==="string"&&x.length<=80).slice(0,100):[];
   if(!["delivered","seen"].includes(status)||!ids.length)return json({ok:true});
   if(status==="seen"){
    const {error}=await db.from("chat_messages").update({payload:null,seen_at:now}).eq("room_id",room.id).neq("sender_id",deviceId).in("message_id",ids);if(error)throw error;
   }else{
    const {error}=await db.from("chat_messages").update({delivered_at:now}).eq("room_id",room.id).neq("sender_id",deviceId).in("message_id",ids);if(error)throw error;
   }
   await db.from("chat_pin_rooms").update({last_activity_at:now}).eq("id",room.id);
   return json({ok:true,deleted:status==="seen"});
  }
  if(action==="delete-request"){
   if(!deviceHash)return json({error:"This device has no valid connection identity."},400);
   const cutoffActive=new Date(Date.now()-120*1000).toISOString();
   const {data:active,error:activeErr}=await db.from("chat_pin_connections").select("device_hash").eq("room_id",room.id).gte("last_seen_at",cutoffActive);
   if(activeErr)throw activeErr;
   const activeHashes=(active||[]).map((x:any)=>x.device_hash);
   if(!activeHashes.includes(deviceHash))return json({error:"This device is not currently connected to this chat."},403);
   const {error:insertErr}=await db.from("chat_pin_delete_requests").upsert({room_id:room.id,device_hash:deviceHash,requested_at:now},{onConflict:"room_id,device_hash"});
   if(insertErr)throw insertErr;
   const cutoff=new Date(Date.now()-24*60*60*1000).toISOString();
   const {data:requests,error:requestErr}=await db.from("chat_pin_delete_requests").select("device_hash").eq("room_id",room.id).gte("requested_at",cutoff);
   if(requestErr)throw requestErr;
   const confirmations=(requests||[]).filter((x:any)=>activeHashes.includes(x.device_hash));
   if(confirmations.length>=2){const {error:deleteErr}=await db.from("chat_pin_rooms").delete().eq("id",room.id);if(deleteErr)throw deleteErr;return json({ok:true,deleted:true});}
   await db.from("chat_pin_rooms").update({last_activity_at:now}).eq("id",room.id);
   return json({ok:true,deleted:false,waitingForOtherParticipant:true});
  }
  return json({error:"Unknown action"},400);
 }catch(e){console.error(e);return json({error:"Server error. Please retry."},500)}
});