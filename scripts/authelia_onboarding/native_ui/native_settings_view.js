/* Origin: Codex mac-mini-wf; Context: owner-requested useful native account settings.
 * Target: pinned Authelia v4.39.16 SettingsView component only; candidate, not deployed.
 * Aliases Y (React), X (JSX runtime), i (MUI Box), H (Typography), x (Paper),
 * and G (Button) are existing imports in the exact pinned settings-router bundle.
 */
qr=function(){
    const [account,setAccount]=Y.useState(null),[error,setError]=Y.useState(false),[attempt,setAttempt]=Y.useState(0);
    Y.useEffect(()=>{
        const controller=new AbortController();
        setAccount(null);setError(false);
        const read=async(path)=>{
            const response=await fetch(path,{method:"GET",credentials:"same-origin",cache:"no-store",redirect:"error",headers:{Accept:"application/json"},signal:controller.signal});
            if(!response.ok)throw new Error("Account information unavailable");
            const result=await response.json();
            if(result.status!=="OK"||!result.data||typeof result.data!=="object")throw new Error("Account information unavailable");
            return result.data;
        };
        (async()=>{
            const state=await read("/api/state");
            if(typeof state.username!=="string"||!state.username||![1,2].includes(state.authentication_level))throw new Error("Session unavailable");
            const info=await read("/api/user/info");
            if(typeof info.display_name!=="string"||!["has_totp","has_webauthn","has_duo"].every(key=>typeof info[key]==="boolean"))throw new Error("Account information unavailable");
            if(!controller.signal.aborted)setAccount({state,info});
        })().catch(()=>{if(!controller.signal.aborted)setError(true)});
        return()=>controller.abort();
    },[attempt]);
    const heading={color:"#182936",fontWeight:700},muted={color:"#5b6c78",lineHeight:1.65};
    const panel={border:"1px solid #e1e7ec",borderRadius:"16px",background:"#fff",boxShadow:"0 8px 28px rgba(30,58,95,.045)",p:{xs:2.5,sm:3.5}};
    const button={textTransform:"none",fontFamily:"inherit",fontWeight:700,borderRadius:"9px",minHeight:46,px:2.2,boxShadow:"none",alignSelf:"flex-start","&:focus-visible":{outline:"3px solid #86b7fe",outlineOffset:3}};
    const text=(value,sx={},props={})=>X.jsx(H,{sx:{fontFamily:"inherit",...muted,...sx},...props,children:value});
    const label=(title,value)=>X.jsxs(i,{component:"div",sx:{minWidth:0},children:[text(title,{fontSize:12,fontWeight:700,textTransform:"uppercase",letterSpacing:".06em",mb:.65}),text(value,{color:"#182936",fontSize:16,fontWeight:600,overflowWrap:"anywhere"})]});
    const action=(title,description,href,caption,primary=false)=>X.jsxs(x,{component:"section",variant:"outlined",sx:{...panel,display:"flex",flexDirection:"column",gap:1.4},children:[text(title,{...heading,fontSize:21},{component:"h2"}),text(description,{fontSize:14.5,flexGrow:1}),X.jsx(G,{component:"a",href,variant:primary?"contained":"outlined",sx:{...button,color:primary?"#fff":"#126d70",backgroundColor:primary?"#126d70":"transparent",borderColor:"#b9d6d5","&:hover":{backgroundColor:primary?"#0b5558":"#eef7f6",borderColor:"#126d70",boxShadow:"none"}},children:caption})]});
    const status=(title,registered)=>X.jsxs(i,{sx:{display:"flex",alignItems:"center",justifyContent:"space-between",gap:2,py:1.1,borderBottom:"1px solid #eef2f7","&:last-child":{borderBottom:0}},children:[text(title,{fontSize:14,color:"#182936",fontWeight:500}),text(registered?"Eingerichtet":"Nicht eingerichtet",{fontSize:12.5,fontWeight:600,color:registered?"#1f6b50":"#5b6c78",backgroundColor:registered?"#edf7f1":"#f2f5f9",borderRadius:"6px",px:1.1,py:.45,whiteSpace:"nowrap"})]});
    const methodNames={totp:"Authenticator-App",webauthn:"Passkey / Sicherheitsschlüssel",mobile_push:"Push-Bestätigung"};
    const emails=account&&Array.isArray(account.info.emails)?account.info.emails.filter(value=>typeof value==="string"):[];
    return X.jsxs(i,{id:"jarvis-account-overview",sx:{fontFamily:"-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif",maxWidth:1184,mx:"auto",px:{xs:2.5,sm:0},py:{xs:3,sm:2},pb:5},children:[
        X.jsxs(i,{component:"header",sx:{mb:3.5},children:[text("DEIN KONTO",{fontSize:12,fontWeight:700,letterSpacing:".12em",color:"#126d70",mb:1}),text("Kontoeinstellungen",{...heading,fontSize:{xs:30,sm:34},lineHeight:1.2,letterSpacing:"-.045em",mb:1.3},{component:"h1"}),text("Behalte deine Anmeldung im Blick und verwalte deine Sicherheit.",{fontSize:16})]}),
        !account?X.jsxs(x,{variant:"outlined",sx:{...panel,mb:3},children:[text(error?"Kontodaten konnten nicht geladen werden.":"Kontodaten werden geladen …",{...heading,fontSize:17},{role:"status","aria-live":"polite"}),error?X.jsxs(i,{sx:{mt:1.5},children:[text("Lade die Daten erneut. Falls deine Sitzung abgelaufen ist, melde dich wieder an.",{fontSize:14,mb:2}),X.jsx(G,{variant:"outlined",onClick:()=>setAttempt(value=>value+1),sx:button,children:"Erneut laden"}),X.jsx(G,{component:"a",href:"/",sx:{...button,ml:1},children:"Zur Anmeldung"})]}):null]}):X.jsxs(x,{component:"section",variant:"outlined",sx:{...panel,mb:3},children:[
            X.jsxs(i,{sx:{display:"flex",alignItems:"center",gap:1.5,mb:2.8},children:[X.jsx(i,{"aria-hidden":true,sx:{width:48,height:48,borderRadius:"14px",backgroundColor:"#eef7f6",color:"#126d70",display:"flex",alignItems:"center",justifyContent:"center",fontSize:23,fontWeight:700,flexShrink:0},children:(account.info.display_name||account.state.username).charAt(0).toUpperCase()}),X.jsxs(i,{sx:{minWidth:0},children:[text(account.info.display_name||account.state.username,{...heading,fontSize:22,overflowWrap:"anywhere"},{component:"h2"}),text(account.state.authentication_level===2?"Anmeldung mit zweitem Faktor bestätigt":"Angemeldet",{fontSize:13.5})]})]}),
            X.jsxs(i,{sx:{display:"grid",gridTemplateColumns:{xs:"1fr",sm:"1fr 1fr"},gap:{xs:2,sm:3}},children:[label("Benutzername",account.state.username),label("E-Mail",emails.length?emails.join(", "):"Keine E-Mail in der Sitzung verfügbar")]}),
            X.jsxs(i,{sx:{borderTop:"1px solid #e8edf4",mt:3,pt:2.2},children:[text("Hinterlegte Anmeldeverfahren",{...heading,fontSize:15,mb:.4},{component:"h3"}),status("Authenticator-App (Einmalcode)",account.info.has_totp),status("Passkey / Sicherheitsschlüssel",account.info.has_webauthn),account.info.has_duo?status("Push-Bestätigung",true):null,methodNames[account.info.method]?text("Bevorzugte Methode: "+methodNames[account.info.method],{fontSize:12.5,mt:1.6}):null,text("Welche Verfahren du verwenden kannst, siehst du in den Sicherheitseinstellungen.",{fontSize:12.5,mt:.8})]})
        ]}),
        X.jsxs(i,{sx:{display:"grid",gridTemplateColumns:{xs:"1fr",sm:"1fr 1fr"},gap:2.5},children:[action("Passwort & Kontosicherheit","Prüfe deine Kontodaten und ändere dein Passwort. Authelia führt dich durch die nötige Bestätigung.","/settings/security","Sicherheit öffnen"),action("Zwei-Faktor-Anmeldung","Verwalte deine Authenticator-App, Passkeys und Sicherheitsschlüssel oder wähle deine bevorzugte Bestätigung.","/settings/two-factor-authentication","Anmeldeverfahren verwalten")]}),
        false?X.jsxs(x,{component:"section",variant:"outlined",sx:{...panel,mt:2.5,borderColor:"#c5dddb",background:"#eef7f6",display:"flex",flexDirection:{xs:"column",sm:"row"},alignItems:{xs:"flex-start",sm:"center"},gap:2.5},children:[X.jsxs(i,{sx:{flexGrow:1},children:[text("ADMINISTRATION",{fontSize:11.5,fontWeight:700,letterSpacing:".1em",color:"#126d70",mb:.75}),text("Benutzerverwaltung",{...heading,fontSize:22,mb:.7},{component:"h2"}),text("Aktiviere Konten, verwalte Jellyfin-Zugriffe und lade neue Personen ein. Administrative Aktionen erfordern deine Zwei-Faktor-Anmeldung.",{fontSize:14.5})]}),X.jsx(G,{component:"a",href:"/onboarding/admin",variant:"contained",sx:{...button,backgroundColor:"#126d70",whiteSpace:{xs:"normal",sm:"nowrap"},"&:hover":{backgroundColor:"#0b5558",boxShadow:"none"}},children:"Verwaltung öffnen"})]}):null,
        X.jsx(i,{component:"footer",sx:{mt:3},children:X.jsx(G,{component:"a",href:"/",sx:{...button,color:"#5b6c78",px:0},children:"Zurück zur Anmeldung"})})
    ]});
};
