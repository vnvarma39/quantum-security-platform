import { useState, useEffect, useRef, useCallback, useMemo } from "react";

/* ─────────────────────────────────────────────
   DATA  – architecture graph + vulnerabilities
───────────────────────────────────────────────*/
const GRAPH_NODES = [
  // External
  { id:"internet",  label:"Internet",       type:"external",   x:50,  y:50,  risk:0.9 },
  { id:"cdn",       label:"CDN Edge",       type:"external",   x:170, y:50,  risk:0.4 },
  // Perimeter
  { id:"waf",       label:"WAF",            type:"security",   x:50,  y:140, risk:0.3 },
  { id:"lb",        label:"Load Balancer",  type:"infra",      x:170, y:140, risk:0.2 },
  // Services
  { id:"apigw",     label:"API Gateway",    type:"service",    x:110, y:230, risk:0.6 },
  { id:"auth",      label:"Auth Service",   type:"service",    x:30,  y:320, risk:0.75 },
  { id:"userapi",   label:"User API",       type:"service",    x:130, y:320, risk:0.55 },
  { id:"payapi",    label:"Payment API",    type:"service",    x:230, y:320, risk:0.8 },
  // Internal
  { id:"msgqueue",  label:"Message Queue",  type:"infra",      x:80,  y:420, risk:0.35 },
  { id:"worker",    label:"Job Worker",     type:"service",    x:180, y:420, risk:0.5 },
  { id:"parser",    label:"Pkg Parser",     type:"service",    x:290, y:320, risk:0.85 },
  // Data
  { id:"userdb",    label:"User DB",        type:"data",       x:30,  y:510, risk:0.7 },
  { id:"paydb",     label:"Payment DB",     type:"data",       x:130, y:510, risk:0.9 },
  { id:"cache",     label:"Redis Cache",    type:"data",       x:230, y:510, risk:0.45 },
  { id:"filestore", label:"File Store",     type:"data",       x:310, y:430, risk:0.6 },
  // Admin
  { id:"admin",     label:"Admin Panel",   type:"service",    x:360, y:230, risk:0.88 },
  { id:"metrics",   label:"Metrics",        type:"infra",      x:360, y:140, risk:0.25 },
];

const GRAPH_EDGES = [
  { s:"internet", t:"waf",      type:"public" },
  { s:"internet", t:"cdn",      type:"public" },
  { s:"cdn",      t:"lb",       type:"public" },
  { s:"waf",      t:"lb",       type:"filtered" },
  { s:"lb",       t:"apigw",    type:"internal" },
  { s:"apigw",    t:"auth",     type:"internal" },
  { s:"apigw",    t:"userapi",  type:"internal" },
  { s:"apigw",    t:"payapi",   type:"internal" },
  { s:"apigw",    t:"parser",   type:"internal" },
  { s:"auth",     t:"userdb",   type:"internal" },
  { s:"auth",     t:"cache",    type:"internal" },
  { s:"userapi",  t:"userdb",   type:"internal" },
  { s:"userapi",  t:"msgqueue", type:"internal" },
  { s:"payapi",   t:"paydb",    type:"internal" },
  { s:"payapi",   t:"worker",   type:"internal" },
  { s:"parser",   t:"filestore",type:"internal" },
  { s:"parser",   t:"worker",   type:"internal" },
  { s:"msgqueue", t:"worker",   type:"internal" },
  { s:"worker",   t:"paydb",    type:"internal" },
  { s:"admin",    t:"userdb",   type:"privileged" },
  { s:"admin",    t:"paydb",    type:"privileged" },
  { s:"admin",    t:"apigw",    type:"privileged" },
  { s:"metrics",  t:"admin",    type:"internal" },
  { s:"lb",       t:"admin",    type:"internal" },
];

const ATTACK_PATHS = [
  {
    id:"AP-001",
    name:"Supply Chain → DB Exfiltration",
    severity:"Critical",
    steps:["internet","waf","lb","apigw","parser","worker","paydb"],
    vulns:[
      { nodeId:"parser",  cve:"CVE-2024-031", type:"Buffer Overflow",  desc:"Unchecked input length in package parser" },
      { nodeId:"worker",  cve:"CVE-2024-044", type:"Privilege Escalation", desc:"Worker process runs as root unnecessarily" },
      { nodeId:"paydb",   cve:"CVE-2024-052", type:"SQL Injection",    desc:"Unparameterized query in payment record fetch" },
    ],
    patches:[
      { nodeId:"parser", label:"Bounds Check", code:`// parser.c:142\nvoid parse_pkg(char *buf, int len) {\n  if (len > MAX_PKG) { log_warn(); return; }\n  char local[MAX_PKG];\n  memcpy(local, buf, len);\n}`, risk:0.06, behavior:0.99 },
      { nodeId:"worker", label:"Drop Privileges", code:`// worker.go:88\nfunc initWorker() {\n  if err := syscall.Setuid(workerUID); err != nil {\n    log.Fatal("privilege drop failed:", err)\n  }\n}`, risk:0.08, behavior:0.98 },
      { nodeId:"paydb",  label:"Parameterized Query", code:`// payments.py:203\ndef get_record(id):\n    return db.execute(\n        "SELECT * FROM pay WHERE id=?",\n        (id,)  # safe binding\n    )`, risk:0.04, behavior:0.99 },
    ],
  },
  {
    id:"AP-002",
    name:"Auth Bypass → User Data Theft",
    severity:"High",
    steps:["internet","waf","lb","apigw","auth","userdb"],
    vulns:[
      { nodeId:"auth",    cve:"CVE-2024-019", type:"JWT Forgery",      desc:"HS256 secret too short, brute-forceable" },
      { nodeId:"userdb",  cve:"CVE-2024-028", type:"Broken Access Control", desc:"No row-level security on user table" },
    ],
    patches:[
      { nodeId:"auth",   label:"RS256 Migration", code:`// auth.js:31\nconst token = jwt.sign(payload, privateKey, {\n  algorithm: "RS256",  // asymmetric\n  expiresIn: "15m",\n  audience: SERVICE_ID,\n});`, risk:0.05, behavior:0.99 },
      { nodeId:"userdb", label:"Row-Level Security", code:`-- migrations/rls.sql\nALTER TABLE users ENABLE ROW LEVEL SECURITY;\nCREATE POLICY user_self ON users\n  USING (id = current_setting('app.uid')::int);`, risk:0.07, behavior:0.97 },
    ],
  },
  {
    id:"AP-003",
    name:"Admin Panel Pivot",
    severity:"High",
    steps:["internet","cdn","lb","admin","paydb"],
    vulns:[
      { nodeId:"admin",  cve:"CVE-2024-007", type:"SSRF",             desc:"Admin proxies arbitrary internal URLs" },
      { nodeId:"paydb",  cve:"CVE-2024-052", type:"SQL Injection",    desc:"Unparameterized payment query" },
    ],
    patches:[
      { nodeId:"admin",  label:"SSRF Allowlist", code:`// admin/proxy.ts:67\nconst ALLOWED = new Set(["metrics","cache"]);\nif (!ALLOWED.has(new URL(target).hostname))\n  throw new ForbiddenError("blocked target");`, risk:0.06, behavior:0.98 },
      { nodeId:"paydb",  label:"Parameterized Query", code:`// payments.py:203\ndef get_record(id):\n    return db.execute(\n        "SELECT * FROM pay WHERE id=?", (id,)\n    )`, risk:0.04, behavior:0.99 },
    ],
  },
];

/* ─────────────────────────────────────────
   HELPERS
───────────────────────────────────────────*/
const NODE_COLORS = { external:"#f97316", security:"#22d3ee", infra:"#64748b", service:"#818cf8", data:"#f472b6" };
const SEVERITY_COL = { Critical:"#ff3366", High:"#f97316", Medium:"#eab308" };
const PHASE_NAMES = ["Energy Init","Quantum Walk","Superposition","Decoherence","Path Collapse","Graph Resolved"];

function lerp(a,b,t){ return a+(b-a)*t; }
function rand(min,max){ return min+Math.random()*(max-min); }

/* ─────────────────────────────────────────
   SUBCOMPONENTS
───────────────────────────────────────────*/

function Orb({ x, y, r, color, pulse, label, selected, onClick }){
  return (
    <g onClick={onClick} style={{cursor:"pointer"}}>
      {pulse && <circle cx={x} cy={y} r={r+8} fill="none" stroke={color} strokeWidth="1" opacity="0.4">
        <animate attributeName="r" from={r+4} to={r+20} dur="1.5s" repeatCount="indefinite"/>
        <animate attributeName="opacity" from="0.5" to="0" dur="1.5s" repeatCount="indefinite"/>
      </circle>}
      {selected && <circle cx={x} cy={y} r={r+5} fill="none" stroke={color} strokeWidth="2" opacity="0.8"/>}
      <circle cx={x} cy={y} r={r} fill={color+"22"} stroke={color} strokeWidth={selected?2:1.2}/>
      <text x={x} y={y+1} textAnchor="middle" dominantBaseline="middle" fontSize="7" fill={color} fontFamily="monospace" fontWeight="700">{label.slice(0,6)}</text>
    </g>
  );
}

function QuantumOrb({size=80}){
  return(
    <div style={{width:size,height:size,position:"relative",flexShrink:0}}>
      <svg width={size} height={size} viewBox="0 0 80 80">
        <defs>
          <radialGradient id="orbg" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#00ffcc" stopOpacity="0.3"/>
            <stop offset="100%" stopColor="#00ffcc" stopOpacity="0"/>
          </radialGradient>
        </defs>
        <circle cx="40" cy="40" r="38" fill="url(#orbg)" stroke="#00ffcc22" strokeWidth="1"/>
        {[0,60,120,180,240,300].map((deg,i)=>(
          <ellipse key={i} cx="40" cy="40" rx="34" ry="12" fill="none" stroke="#00ffcc" strokeWidth="0.6" opacity="0.3"
            transform={`rotate(${deg} 40 40)`}>
            <animateTransform attributeName="transform" type="rotate" from={`${deg} 40 40`} to={`${deg+360} 40 40`} dur={`${3+i*0.4}s`} repeatCount="indefinite"/>
          </ellipse>
        ))}
        <circle cx="40" cy="40" r="8" fill="#00ffcc" opacity="0.9">
          <animate attributeName="r" values="6;10;6" dur="2s" repeatCount="indefinite"/>
          <animate attributeName="opacity" values="0.9;0.5;0.9" dur="2s" repeatCount="indefinite"/>
        </circle>
      </svg>
    </div>
  );
}

function MiniSparkline({data, color="#00ffcc", h=32}){
  if(!data||data.length<2) return null;
  const mn=Math.min(...data), mx=Math.max(...data), rng=mx-mn||1;
  const pts=data.map((v,i)=>`${(i/(data.length-1))*100},${h-(((v-mn)/rng)*h)}`).join(" ");
  return(
    <svg width="100%" height={h} viewBox={`0 0 100 ${h}`} preserveAspectRatio="none">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5"/>
      <polygon points={`0,${h} ${pts} 100,${h}`} fill={color} opacity="0.12"/>
    </svg>
  );
}

/* ─────────────────────────────────────────
   MAIN APP
───────────────────────────────────────────*/
export default function App(){
  /* state */
  const [activeTab, setActiveTab]   = useState("graph");
  const [selectedPath, setSelectedPath] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [phase, setPhase]           = useState(-1);
  const [progress, setProgress]     = useState(0);
  const [qubits, setQubits]         = useState(Array(16).fill(0));
  const [energyHist, setEnergyHist] = useState([]);
  const [walkPos, setWalkPos]       = useState(null);
  const [log, setLog]               = useState([]);
  const [patchStage, setPatchStage] = useState("idle"); // idle|synthesizing|validating|done
  const [patchProgress, setPatchProgress] = useState(0);
  const [patchPhase, setPatchPhase] = useState(-1);
  const [testResults, setTestResults] = useState({});
  const [appliedPatches, setAppliedPatches] = useState(new Set());
  const [hoveredNode, setHoveredNode] = useState(null);
  const [scanSweep, setScanSweep]   = useState(0);
  const [particles, setParticles]   = useState([]);
  const intervalRef  = useRef(null);
  const patchRef     = useRef(null);
  const logRef       = useRef(null);
  const sweepRef     = useRef(null);

  const activePath = selectedPath != null ? ATTACK_PATHS[selectedPath] : null;

  /* background sweep animation */
  useEffect(()=>{
    sweepRef.current = setInterval(()=> setScanSweep(p=>(p+1)%360), 50);
    return ()=> clearInterval(sweepRef.current);
  },[]);

  /* floating particles */
  useEffect(()=>{
    const gen = ()=> setParticles(Array.from({length:20},(_,i)=>({
      id:i, x:rand(0,100), y:rand(0,100),
      size:rand(2,5), op:rand(0.05,0.25),
      col:["#00ffcc","#818cf8","#f97316","#f472b6"][Math.floor(rand(0,4))],
    })));
    gen();
    const iv = setInterval(gen, 4000);
    return ()=> clearInterval(iv);
  },[]);

  const addLog = useCallback((msg,type="info")=>{
    setLog(prev=>[...prev.slice(-80),{msg,type,ts:Date.now()}]);
    setTimeout(()=>{ if(logRef.current) logRef.current.scrollTop=logRef.current.scrollHeight; },30);
  },[]);

  /* ── GRAPH QUANTUM SCAN ── */
  const runGraphScan = useCallback(()=>{
    if(phase>=0 && phase<5) return;
    setPhase(0); setProgress(0); setEnergyHist([]); setLog([]); setSelectedPath(null);
    addLog("[QWALK] Initializing quantum walk on architecture graph","system");
    addLog(`[GRAPH] Nodes: ${GRAPH_NODES.length} | Edges: ${GRAPH_EDGES.length}`,"system");
    addLog("[QAOA] Encoding adjacency matrix into qubit register","system");

    let prog=0, ph=0;
    intervalRef.current = setInterval(()=>{
      prog += rand(1.2,3.5);
      if(prog>100) prog=100;
      setProgress(Math.round(prog));

      // qubit animation
      setQubits(prev=>prev.map((_,i)=>{
        if(ph<2) return rand(0,1)>0.5?1:-1;
        if(ph===3) return rand(0,1)>0.4?(i%2===0?1:-1):0;
        return i<8?1:-1;
      }));

      // energy
      const e = 1-(prog/100);
      setEnergyHist(prev=>[...prev.slice(-80), e+((Math.random()-0.5)*0.08*(1-prog/100))]);

      // walk position (node index)
      setWalkPos(Math.floor(rand(0,GRAPH_NODES.length)));

      // log events
      const events=[
        [`[WALK] Visiting node: ${GRAPH_NODES[Math.floor(rand(0,GRAPH_NODES.length))].label}`,"quantum"],
        [`[TUNNEL] Barrier penetration p=${rand(0.1,0.6).toFixed(3)}`,"quantum"],
        [`[SUPER] State |ψ⟩ across ${Math.floor(rand(3,12))} nodes`,"super"],
        [`[RISK] Edge weight Δ=${rand(0.1,0.9).toFixed(3)}`,"score"],
        [`[PATH] Candidate: ${GRAPH_NODES[Math.floor(rand(0,GRAPH_NODES.length))].label}→${GRAPH_NODES[Math.floor(rand(0,GRAPH_NODES.length))].label}`,"info"],
      ];
      if(Math.random()>0.55) addLog(events[Math.floor(rand(0,events.length))][0], events[Math.floor(rand(0,events.length))][1]);

      const thresholds=[0,18,37,56,75,92];
      const np = thresholds.findIndex((t,i)=>prog<(thresholds[i+1]||101))-1;
      if(np!==ph && np>=0){ ph=np; setPhase(ph); addLog(`[PHASE] → ${PHASE_NAMES[ph]}`,"phase"); }

      if(prog>=100){
        clearInterval(intervalRef.current);
        setPhase(5); setWalkPos(null);
        addLog("[RESULT] Quantum walk complete – 3 attack paths identified","success");
        ATTACK_PATHS.forEach((ap,i)=>{
          setTimeout(()=> addLog(`[PATH] ${ap.id}: ${ap.name} (${ap.severity})`,"success"), i*300+200);
        });
      }
    },70);
  },[phase,addLog]);

  /* ── PATCH SYNTHESIS ── */
  const runPatchSynthesis = useCallback(()=>{
    if(!activePath || patchStage==="synthesizing" || patchStage==="validating") return;
    setPatchStage("synthesizing"); setPatchProgress(0); setPatchPhase(0); setTestResults({});
    addLog(`[QAPS] Starting patch synthesis for ${activePath.id}`,"system");
    addLog(`[QAPS] ${activePath.patches.length} candidate patches to optimize`,"system");

    let prog=0, ph=0;
    patchRef.current = setInterval(()=>{
      prog += rand(1.5,4);
      if(prog>100) prog=100;
      setPatchProgress(Math.round(prog));

      const phNames=["Energy Init","Tunneling","Superposition","Decoherence","Scoring","Optimal"];
      const thr=[0,18,37,56,75,92];
      const np=thr.findIndex((t,i)=>prog<(thr[i+1]||101))-1;
      if(np!==ph && np>=0){ ph=np; setPatchPhase(ph); addLog(`[QAPS] Phase → ${phNames[ph]}`,"phase"); }

      if(Math.random()>0.6) addLog(`[ANNEAL] T=${Math.max(0,100-prog).toFixed(1)}K  ΔE=${rand(0,0.3).toFixed(4)}`,"quantum");

      if(prog>=100){
        clearInterval(patchRef.current);
        setPatchStage("validating");
        addLog("[QAPS] Optimal patches found – running validation suite","success");
        const tests=["static_analysis","bounds_check","fuzzing_afl","regression","sym_exec","sidechannel"];
        tests.forEach((t,i)=>{
          setTimeout(()=>{
            setTestResults(prev=>({...prev,[t]:"running"}));
            setTimeout(()=>{
              const ok=Math.random()>0.07;
              setTestResults(prev=>({...prev,[t]:ok?"pass":"fail"}));
              addLog(`[TEST] ${t}: ${ok?"PASS":"FAIL"}`, ok?"success":"error");
            }, 500+rand(0,400));
          }, i*650+200);
        });
        setTimeout(()=>{ setPatchStage("done"); addLog("[QAPS] Patch synthesis complete – ready to apply","success"); }, tests.length*650+1000);
      }
    },75);
  },[activePath,patchStage,addLog]);

  /* ── derived ── */
  const pathNodeSet  = useMemo(()=> activePath? new Set(activePath.steps):new Set(),[activePath]);
  const vulnNodeSet  = useMemo(()=> activePath? new Set(activePath.vulns.map(v=>v.nodeId)):new Set(),[activePath]);
  const allVulnNodes = useMemo(()=>{
    const s=new Set();
    ATTACK_PATHS.forEach(ap=> ap.vulns.forEach(v=>s.add(v.nodeId)));
    return s;
  },[]);

  const passCount = Object.values(testResults).filter(v=>v==="pass").length;
  const totalTests = Object.keys(testResults).length;

  /* ─── RENDER ─── */
  return(
    <div style={{
      minHeight:"100vh", background:"#03080f",
      fontFamily:"'JetBrains Mono','Fira Code',monospace",
      color:"#b8d4cc", overflow:"hidden", position:"relative",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Bebas+Neue&display=swap');
        *{box-sizing:border-box;}
        ::-webkit-scrollbar{width:3px;background:#050d15;}
        ::-webkit-scrollbar-thumb{background:#00ffcc22;border-radius:3px;}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.35}}
        @keyframes sweep{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}
        @keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
        @keyframes glowPulse{0%,100%{box-shadow:0 0 6px #00ffcc33}50%{box-shadow:0 0 20px #00ffcc77}}
        @keyframes scan{0%{top:-2px}100%{top:100%}}
        .tab{background:none;border:none;cursor:pointer;font-family:inherit;transition:all .2s;}
        .card{border-radius:10px;border:1px solid #0e2030;}
        .btn{border:none;cursor:pointer;font-family:inherit;transition:all .25s;border-radius:8px;}
        .btn:hover:not(:disabled){transform:translateY(-1px);filter:brightness(1.15);}
        .btn:disabled{opacity:0.4;cursor:not-allowed;}
        .node-row{display:flex;align-items:center;gap:8px;padding:6px 8px;border-radius:6px;cursor:pointer;transition:background .15s;}
        .node-row:hover{background:#0a1825;}
        .fadeIn{animation:fadeIn .3s ease both;}
      `}</style>

      {/* BG particles */}
      <div style={{position:"fixed",inset:0,pointerEvents:"none",overflow:"hidden"}}>
        {particles.map(p=>(
          <div key={p.id} style={{
            position:"absolute",left:p.x+"%",top:p.y+"%",
            width:p.size,height:p.size,borderRadius:"50%",
            background:p.col,opacity:p.op,
            boxShadow:`0 0 ${p.size*3}px ${p.col}`,
            transform:"translate(-50%,-50%)",transition:"all 4s ease",
          }}/>
        ))}
        <div style={{position:"absolute",left:0,right:0,height:2,background:"linear-gradient(transparent,#00ffcc06,transparent)",animation:"scan 10s linear infinite"}}/>
      </div>

      {/* ══ HEADER ══ */}
      <header style={{padding:"16px 24px 0",position:"relative",zIndex:10}}>
        <div style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",flexWrap:"wrap",gap:12}}>
          <div style={{display:"flex",alignItems:"center",gap:16}}>
            <QuantumOrb size={60}/>
            <div>
              <div style={{fontSize:9,color:"#00ffcc88",letterSpacing:4,marginBottom:3}}>ANTHROPIC SECURITY LABS // QSIP v3.0</div>
              <h1 style={{
                fontFamily:"'Bebas Neue',sans-serif",fontSize:"clamp(22px,3vw,32px)",
                margin:0,letterSpacing:2,lineHeight:1,
                background:"linear-gradient(135deg,#00ffcc 0%,#38bdf8 40%,#818cf8 70%,#f472b6 100%)",
                WebkitBackgroundClip:"text",WebkitTextFillColor:"transparent",
              }}>Quantum Security Intelligence Platform</h1>
              <div style={{fontSize:10,color:"#3a6055",marginTop:2}}>Graph Analysis · Attack Path Detection · Quantum Patch Synthesis · AI Validation</div>
            </div>
          </div>

          {/* Status pills */}
          <div style={{display:"flex",gap:8,flexWrap:"wrap",alignItems:"center"}}>
            {[
              {label:"Nodes",val:GRAPH_NODES.length,col:"#818cf8"},
              {label:"Edges",val:GRAPH_EDGES.length,col:"#38bdf8"},
              {label:"Paths Found",val:phase===5?ATTACK_PATHS.length:"—",col:"#f97316"},
              {label:"Qubits",val:16,col:"#00ffcc"},
            ].map(s=>(
              <div key={s.label} style={{background:"#040d14",border:`1px solid ${s.col}22`,borderRadius:8,padding:"6px 12px",textAlign:"center"}}>
                <div style={{fontSize:16,fontWeight:700,color:s.col}}>{s.val}</div>
                <div style={{fontSize:8,color:"#3a6055",letterSpacing:2}}>{s.label.toUpperCase()}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Tabs */}
        <div style={{display:"flex",gap:2,marginTop:14,borderBottom:"1px solid #0a1e2a"}}>
          {[
            ["graph","Architecture Graph"],
            ["paths","Attack Paths"],
            ["synthesis","Patch Synthesis"],
            ["quantum","Quantum State"],
            ["log","Event Log"],
          ].map(([id,lbl])=>(
            <button key={id} className="tab" onClick={()=>setActiveTab(id)} style={{
              padding:"7px 14px",fontSize:10,letterSpacing:1.5,
              color:activeTab===id?"#00ffcc":"#3a6055",
              borderBottom:activeTab===id?"2px solid #00ffcc":"2px solid transparent",
              fontWeight:activeTab===id?700:400,
            }}>{lbl.toUpperCase()}</button>
          ))}
        </div>
      </header>

      {/* ══ BODY ══ */}
      <div style={{display:"grid",gridTemplateColumns:"260px 1fr",gap:16,padding:"14px 24px 24px",maxWidth:1440,position:"relative",zIndex:5}}>

        {/* ─── LEFT SIDEBAR ─── */}
        <div style={{display:"flex",flexDirection:"column",gap:12}}>

          {/* Scan control */}
          <div className="card" style={{background:"#040d14",padding:14}}>
            <div style={{fontSize:8,color:"#3a6055",letterSpacing:3,marginBottom:10}}>QUANTUM GRAPH SCAN</div>
            <button className="btn" onClick={runGraphScan}
              disabled={phase>=0 && phase<5}
              style={{
                width:"100%",padding:"11px",
                background:phase===5?"linear-gradient(135deg,#00aa7755,#0088cc55)":"linear-gradient(135deg,#00ffcc11,#38bdf811)",
                border:`1px solid ${phase===5?"#00ffcc66":"#00ffcc33"}`,
                color:"#00ffcc",fontSize:11,fontWeight:700,letterSpacing:2,
                animation:phase>=0&&phase<5?"glowPulse 1.5s infinite":"none",
              }}>
              {phase<0?"▶ SCAN ARCHITECTURE": phase<5?"◈ SCANNING...":"↺ RESCAN"}
            </button>

            {phase>=0 &&(
              <div style={{marginTop:10}}>
                <div style={{display:"flex",justifyContent:"space-between",fontSize:9,color:"#3a6055",marginBottom:4}}>
                  <span>{PHASE_NAMES[Math.min(phase,5)]}</span>
                  <span>{progress}%</span>
                </div>
                <div style={{height:3,background:"#0a1520",borderRadius:2,overflow:"hidden"}}>
                  <div style={{height:"100%",width:progress+"%",transition:"width .2s",
                    background:"linear-gradient(90deg,#818cf8,#00ffcc)",borderRadius:2,boxShadow:"0 0 8px #00ffcc55"}}/>
                </div>
                <div style={{fontSize:9,color:"#3a6055",marginTop:6}}>Phase {Math.min(phase+1,6)}/6</div>
              </div>
            )}
          </div>

          {/* Attack paths list */}
          <div className="card" style={{background:"#040d14",padding:14,flex:1}}>
            <div style={{fontSize:8,color:"#3a6055",letterSpacing:3,marginBottom:10}}>
              DETECTED ATTACK PATHS {phase===5&&<span style={{color:"#00ffcc"}}>({ATTACK_PATHS.length})</span>}
            </div>
            {phase<5 ? (
              <div style={{color:"#3a6055",fontSize:11,textAlign:"center",padding:"24px 0"}}>
                {phase<0?"Run scan to detect paths":"Analyzing..."}
              </div>
            ):(
              <div style={{display:"flex",flexDirection:"column",gap:6}}>
                {ATTACK_PATHS.map((ap,i)=>(
                  <div key={ap.id}
                    onClick={()=>{ setSelectedPath(i); setActiveTab("paths"); }}
                    className="fadeIn"
                    style={{
                      padding:"9px 10px",borderRadius:8,cursor:"pointer",transition:"all .2s",
                      background:selectedPath===i?"#071a14":"#060f18",
                      border:`1px solid ${selectedPath===i?SEVERITY_COL[ap.severity]+"66":"#0e2030"}`,
                      animationDelay:i*0.1+"s",
                    }}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:3}}>
                      <span style={{fontSize:10,color:"#00ffcc",fontWeight:700}}>{ap.id}</span>
                      <span style={{fontSize:8,padding:"1px 6px",borderRadius:5,
                        background:SEVERITY_COL[ap.severity]+"22",color:SEVERITY_COL[ap.severity],
                        border:`1px solid ${SEVERITY_COL[ap.severity]}44`}}>{ap.severity}</span>
                    </div>
                    <div style={{fontSize:11,color:"#c8e6e0",fontWeight:600,marginBottom:2}}>{ap.name}</div>
                    <div style={{fontSize:9,color:"#3a6055"}}>{ap.steps.length} hops · {ap.vulns.length} CVEs</div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Selected path vulns */}
          {activePath &&(
            <div className="card fadeIn" style={{background:"#040d14",padding:14}}>
              <div style={{fontSize:8,color:"#f97316",letterSpacing:3,marginBottom:10}}>VULNERABILITIES</div>
              {activePath.vulns.map(v=>(
                <div key={v.cve} style={{marginBottom:10,paddingBottom:10,borderBottom:"1px solid #0e2030"}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:2}}>
                    <span style={{fontSize:9,color:"#f97316",fontWeight:700}}>{v.cve}</span>
                    <span style={{fontSize:8,color:"#3a6055"}}>{GRAPH_NODES.find(n=>n.id===v.nodeId)?.label}</span>
                  </div>
                  <div style={{fontSize:10,color:"#818cf8"}}>{v.type}</div>
                  <div style={{fontSize:9,color:"#3a6055",marginTop:2}}>{v.desc}</div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* ─── RIGHT MAIN ─── */}
        <div>

          {/* ══ GRAPH TAB ══ */}
          {activeTab==="graph"&&(
            <div className="card fadeIn" style={{background:"#040d14",padding:16,height:"calc(100vh - 180px)",overflow:"hidden"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
                <div style={{fontSize:8,color:"#3a6055",letterSpacing:3}}>SOFTWARE ARCHITECTURE GRAPH</div>
                <div style={{display:"flex",gap:12,fontSize:9,color:"#3a6055"}}>
                  {Object.entries(NODE_COLORS).map(([t,c])=>(
                    <span key={t}><span style={{color:c}}>●</span> {t}</span>
                  ))}
                </div>
              </div>

              <svg width="100%" height="calc(100% - 32px)" viewBox="0 0 420 580" style={{overflow:"visible"}}>
                <defs>
                  <filter id="glow">
                    <feGaussianBlur stdDeviation="2" result="blur"/>
                    <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                  </filter>
                  <marker id="arr" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
                    <path d="M0,0 L6,3 L0,6 Z" fill="#1a3050"/>
                  </marker>
                  <marker id="arr-active" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
                    <path d="M0,0 L6,3 L0,6 Z" fill="#f97316"/>
                  </marker>
                </defs>

                {/* Edges */}
                {GRAPH_EDGES.map((e,i)=>{
                  const s=GRAPH_NODES.find(n=>n.id===e.s);
                  const t=GRAPH_NODES.find(n=>n.id===e.t);
                  if(!s||!t) return null;
                  const isActive = activePath &&
                    activePath.steps.includes(e.s) && activePath.steps.includes(e.t) &&
                    Math.abs(activePath.steps.indexOf(e.s)-activePath.steps.indexOf(e.t))===1;
                  return(
                    <line key={i} x1={s.x} y1={s.y} x2={t.x} y2={t.y}
                      stroke={isActive?"#f97316":"#0e2535"}
                      strokeWidth={isActive?2:1}
                      opacity={isActive?0.9:0.5}
                      markerEnd={isActive?"url(#arr-active)":"url(#arr)"}
                      strokeDasharray={isActive?"none":"4 3"}
                      filter={isActive?"url(#glow)":undefined}>
                      {isActive&&<animate attributeName="stroke-dashoffset" from="0" to="-20" dur="1s" repeatCount="indefinite"/>}
                    </line>
                  );
                })}

                {/* Nodes */}
                {GRAPH_NODES.map(n=>{
                  const col = NODE_COLORS[n.type];
                  const isVuln  = allVulnNodes.has(n.id);
                  const inPath  = pathNodeSet.has(n.id);
                  const isWalk  = phase>=1&&phase<5 && walkPos!==null && GRAPH_NODES[walkPos]?.id===n.id;
                  const displayCol = isVuln?(inPath?"#f97316":col):col;
                  return(
                    <Orb key={n.id}
                      x={n.x} y={n.y} r={inPath?11:8}
                      color={displayCol}
                      pulse={isVuln||isWalk}
                      label={n.label}
                      selected={selectedNode===n.id||inPath}
                      onClick={()=>setSelectedNode(selectedNode===n.id?null:n.id)}
                    />
                  );
                })}

                {/* Quantum walk particle */}
                {phase>=1&&phase<5&&walkPos!==null&&(()=>{
                  const n=GRAPH_NODES[walkPos];
                  if(!n) return null;
                  return(
                    <g>
                      <circle cx={n.x} cy={n.y} r="18" fill="none" stroke="#818cf8" strokeWidth="1" opacity="0.5">
                        <animate attributeName="r" from="12" to="28" dur="0.8s" repeatCount="indefinite"/>
                        <animate attributeName="opacity" from="0.6" to="0" dur="0.8s" repeatCount="indefinite"/>
                      </circle>
                      <circle cx={n.x} cy={n.y} r="5" fill="#818cf8" opacity="0.9">
                        <animate attributeName="r" values="4;7;4" dur="0.6s" repeatCount="indefinite"/>
                      </circle>
                    </g>
                  );
                })()}
              </svg>

              {/* Node detail popup */}
              {selectedNode&&(()=>{
                const n=GRAPH_NODES.find(x=>x.id===selectedNode);
                if(!n) return null;
                const nvulns = ATTACK_PATHS.flatMap(ap=>ap.vulns).filter(v=>v.nodeId===n.id);
                return(
                  <div className="fadeIn" style={{
                    position:"absolute",top:60,right:24,
                    background:"#030a14",border:"1px solid #00ffcc33",
                    borderRadius:10,padding:14,width:220,zIndex:20,
                  }}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                      <span style={{color:NODE_COLORS[n.type],fontWeight:700,fontSize:12}}>{n.label}</span>
                      <button onClick={()=>setSelectedNode(null)} style={{background:"none",border:"none",color:"#3a6055",cursor:"pointer",fontSize:14}}>×</button>
                    </div>
                    <div style={{fontSize:9,color:"#3a6055",marginBottom:6}}>Type: <span style={{color:"#b8d4cc"}}>{n.type}</span></div>
                    <div style={{fontSize:9,marginBottom:8}}>
                      Risk: <span style={{color:n.risk>0.7?"#f97316":n.risk>0.4?"#eab308":"#00ffcc"}}>{(n.risk*100).toFixed(0)}%</span>
                      <div style={{height:3,background:"#0a1520",borderRadius:2,marginTop:4}}>
                        <div style={{height:"100%",width:(n.risk*100)+"%",background:n.risk>0.7?"#f97316":n.risk>0.4?"#eab308":"#00ffcc",borderRadius:2}}/>
                      </div>
                    </div>
                    {nvulns.length>0&&(
                      <div>
                        <div style={{fontSize:8,color:"#f97316",letterSpacing:2,marginBottom:4}}>VULNERABILITIES</div>
                        {nvulns.map(v=>(
                          <div key={v.cve} style={{fontSize:9,color:"#f472b6",marginBottom:2}}>⚠ {v.cve} – {v.type}</div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })()}
            </div>
          )}

          {/* ══ ATTACK PATHS TAB ══ */}
          {activeTab==="paths"&&(
            <div style={{display:"flex",flexDirection:"column",gap:14}} className="fadeIn">
              {!activePath?(
                <div className="card" style={{background:"#040d14",padding:40,textAlign:"center",color:"#3a6055"}}>
                  {phase<5?"Run graph scan first, then select a detected attack path.":"Select an attack path from the sidebar."}
                </div>
              ):(
                <>
                  {/* Path header */}
                  <div className="card" style={{background:"#040d14",padding:16}}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",flexWrap:"wrap",gap:10}}>
                      <div>
                        <div style={{display:"flex",gap:10,alignItems:"center",marginBottom:4}}>
                          <span style={{fontSize:11,color:"#00ffcc",fontWeight:700}}>{activePath.id}</span>
                          <span style={{fontSize:9,padding:"2px 8px",borderRadius:6,
                            background:SEVERITY_COL[activePath.severity]+"22",
                            color:SEVERITY_COL[activePath.severity],
                            border:`1px solid ${SEVERITY_COL[activePath.severity]}44`}}>{activePath.severity}</span>
                        </div>
                        <div style={{fontSize:15,fontWeight:700,color:"#e8f4f0"}}>{activePath.name}</div>
                      </div>
                      <button className="btn" onClick={()=>{ setActiveTab("synthesis"); runPatchSynthesis(); }}
                        disabled={patchStage==="synthesizing"||patchStage==="validating"}
                        style={{padding:"10px 18px",background:"linear-gradient(135deg,#f9731622,#f97316)",
                          border:"1px solid #f9731655",color:"#fff",fontSize:11,fontWeight:700,letterSpacing:1}}>
                        ⚡ SYNTHESIZE PATCHES
                      </button>
                    </div>

                    {/* Attack path chain */}
                    <div style={{marginTop:14,overflowX:"auto"}}>
                      <div style={{display:"flex",alignItems:"center",gap:4,minWidth:"max-content"}}>
                        {activePath.steps.map((nodeId,i)=>{
                          const n=GRAPH_NODES.find(x=>x.id===nodeId);
                          const isVuln=vulnNodeSet.has(nodeId);
                          const col=isVuln?"#f97316":NODE_COLORS[n?.type||"service"];
                          return(
                            <div key={nodeId} style={{display:"flex",alignItems:"center",gap:4}}>
                              <div style={{padding:"5px 10px",borderRadius:6,
                                background:isVuln?"#f9731622":"#060f18",
                                border:`1px solid ${col}55`,textAlign:"center"}}>
                                <div style={{fontSize:8,color:col,fontWeight:700,letterSpacing:1}}>{n?.label}</div>
                                <div style={{fontSize:7,color:"#3a6055"}}>{n?.type}</div>
                                {isVuln&&<div style={{fontSize:7,color:"#f97316",marginTop:1}}>⚠ CVE</div>}
                              </div>
                              {i<activePath.steps.length-1&&(
                                <div style={{fontSize:14,color:"#f97316",opacity:0.6}}>→</div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </div>

                  {/* Vuln cards */}
                  <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(280px,1fr))",gap:12}}>
                    {activePath.vulns.map(v=>{
                      const n=GRAPH_NODES.find(x=>x.id===v.nodeId);
                      return(
                        <div key={v.cve} className="card fadeIn" style={{background:"#040d14",padding:14}}>
                          <div style={{display:"flex",justifyContent:"space-between",marginBottom:6}}>
                            <span style={{fontSize:10,color:"#f97316",fontWeight:700}}>{v.cve}</span>
                            <span style={{fontSize:9,color:"#818cf8"}}>{n?.label}</span>
                          </div>
                          <div style={{fontSize:12,color:"#e8f4f0",fontWeight:600,marginBottom:4}}>{v.type}</div>
                          <div style={{fontSize:10,color:"#3a6055"}}>{v.desc}</div>
                        </div>
                      );
                    })}
                  </div>
                </>
              )}
            </div>
          )}

          {/* ══ PATCH SYNTHESIS TAB ══ */}
          {activeTab==="synthesis"&&(
            <div style={{display:"flex",flexDirection:"column",gap:14}} className="fadeIn">
              {!activePath?(
                <div className="card" style={{background:"#040d14",padding:40,textAlign:"center",color:"#3a6055"}}>
                  Select an attack path first to synthesize patches.
                </div>
              ):(
                <>
                  {/* Synthesis progress */}
                  <div className="card" style={{background:"#040d14",padding:16}}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
                      <div style={{fontSize:8,color:"#3a6055",letterSpacing:3}}>QUANTUM ANNEALING – PATCH OPTIMIZATION</div>
                      {patchStage!=="idle"&&<div style={{fontSize:10,color:"#00ffcc"}}>{patchProgress}%</div>}
                    </div>

                    {patchStage==="idle"&&(
                      <button className="btn" onClick={runPatchSynthesis} style={{
                        padding:"11px 20px",background:"linear-gradient(135deg,#818cf822,#818cf8)",
                        border:"1px solid #818cf866",color:"#fff",fontSize:11,fontWeight:700,letterSpacing:2}}>
                        ▶ RUN ANNEALING
                      </button>
                    )}

                    {(patchStage==="synthesizing"||patchStage==="validating"||patchStage==="done")&&(
                      <>
                        {/* Annealing phases */}
                        <div style={{display:"flex",gap:4,marginBottom:10,flexWrap:"wrap"}}>
                          {["Energy Init","Tunneling","Superposition","Decoherence","Scoring","Optimal"].map((ph,i)=>(
                            <div key={ph} style={{fontSize:8,padding:"2px 8px",borderRadius:4,
                              background:patchPhase>=i?"#00ffcc22":"#060f18",
                              color:patchPhase>=i?"#00ffcc":"#3a6055",
                              border:`1px solid ${patchPhase>=i?"#00ffcc44":"#0e2030"}`}}>
                              {ph}
                            </div>
                          ))}
                        </div>
                        <div style={{height:4,background:"#0a1520",borderRadius:2,overflow:"hidden",marginBottom:10}}>
                          <div style={{height:"100%",width:patchProgress+"%",transition:"width .2s",
                            background:"linear-gradient(90deg,#818cf8,#f472b6,#00ffcc)",
                            borderRadius:2,boxShadow:"0 0 8px #00ffcc55"}}/>
                        </div>

                        {/* Test results */}
                        {totalTests>0&&(
                          <div>
                            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
                              <div style={{fontSize:8,color:"#3a6055",letterSpacing:3}}>VALIDATION SUITE</div>
                              <div style={{fontSize:10,color:passCount===totalTests?"#00ffcc":"#eab308"}}>
                                {passCount}/{totalTests} PASS
                              </div>
                            </div>
                            <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
                              {Object.entries(testResults).map(([name,status])=>{
                                const cols={pass:"#00ffaa",fail:"#ff4466",running:"#f5a623",pending:"#3a6055"};
                                const icons={pass:"✓",fail:"✗",running:"◌",pending:"○"};
                                return(
                                  <span key={name} style={{
                                    display:"inline-flex",alignItems:"center",gap:4,
                                    padding:"2px 8px",borderRadius:10,fontSize:9,fontFamily:"monospace",
                                    background:cols[status]+"11",border:`1px solid ${cols[status]}44`,color:cols[status],
                                    animation:status==="running"?"pulse 1s infinite":"none",
                                  }}>
                                    <span style={{fontSize:8}}>{icons[status]}</span>
                                    {name.replace(/_/g," ")}
                                  </span>
                                );
                              })}
                            </div>
                          </div>
                        )}
                      </>
                    )}
                  </div>

                  {/* Patch cards */}
                  {(patchStage==="done"||patchProgress>50)&&activePath.patches.map((p,i)=>{
                    const applied=appliedPatches.has(p.nodeId+p.label);
                    const node=GRAPH_NODES.find(n=>n.id===p.nodeId);
                    return(
                      <div key={i} className="card fadeIn" style={{
                        background:applied?"#041a10":"#040d14",
                        border:`1px solid ${applied?"#00ffcc44":"#0e2030"}`,
                        padding:16,animationDelay:i*0.1+"s",
                        boxShadow:applied?"0 0 16px #00ffcc11":"none",
                      }}>
                        <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:10,flexWrap:"wrap",gap:8}}>
                          <div>
                            <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:3}}>
                              <span style={{fontSize:11,fontWeight:700,color:applied?"#00ffcc":"#818cf8"}}>
                                {applied?"✓ APPLIED: ":""}{p.label}
                              </span>
                              <span style={{fontSize:9,color:"#3a6055"}}>→ {node?.label}</span>
                            </div>
                          </div>
                          <div style={{display:"flex",gap:10,alignItems:"center",flexWrap:"wrap"}}>
                            <div style={{display:"flex",gap:12,fontSize:10,color:"#3a6055"}}>
                              <span>Risk: <span style={{color:"#00ffcc"}}>{(p.risk*100).toFixed(1)}%</span></span>
                              <span>Behavior: <span style={{color:"#00ffcc"}}>{(p.behavior*100).toFixed(1)}%</span></span>
                            </div>
                            {!applied&&patchStage==="done"&&(
                              <button className="btn" onClick={()=>setAppliedPatches(prev=>new Set([...prev,p.nodeId+p.label]))}
                                style={{padding:"6px 14px",background:"#00ffcc22",border:"1px solid #00ffcc55",
                                  color:"#00ffcc",fontSize:10,fontWeight:700}}>
                                APPLY PATCH
                              </button>
                            )}
                          </div>
                        </div>

                        {/* Metric bars */}
                        <div style={{display:"flex",gap:8,marginBottom:10,flexWrap:"wrap"}}>
                          {[
                            {label:"Security",val:1-p.risk},
                            {label:"Behavioral Parity",val:p.behavior},
                            {label:"Minimality",val:0.85+Math.random()*0.12},
                            {label:"Confidence",val:0.88+Math.random()*0.1},
                          ].map(m=>(
                            <div key={m.label} style={{flex:"1 1 120px"}}>
                              <div style={{display:"flex",justifyContent:"space-between",fontSize:8,color:"#3a6055",marginBottom:2}}>
                                <span>{m.label}</span><span style={{color:"#b8d4cc"}}>{(m.val*100).toFixed(0)}%</span>
                              </div>
                              <div style={{height:3,background:"#0a1520",borderRadius:2}}>
                                <div style={{height:"100%",width:(m.val*100)+"%",
                                  background:"linear-gradient(90deg,#818cf8,#00ffcc)",borderRadius:2}}/>
                              </div>
                            </div>
                          ))}
                        </div>

                        <pre style={{
                          margin:0,fontSize:11,lineHeight:1.65,color:"#99ccbb",
                          background:"#020810",padding:12,borderRadius:8,overflow:"auto",
                          borderLeft:`3px solid ${applied?"#00ffcc":"#818cf844"}`,
                        }}>{p.code}</pre>
                      </div>
                    );
                  })}
                </>
              )}
            </div>
          )}

          {/* ══ QUANTUM STATE TAB ══ */}
          {activeTab==="quantum"&&(
            <div style={{display:"flex",flexDirection:"column",gap:14}} className="fadeIn">
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>
                {/* Qubit register */}
                <div className="card" style={{background:"#040d14",padding:16}}>
                  <div style={{fontSize:8,color:"#3a6055",letterSpacing:3,marginBottom:14}}>16-QUBIT REGISTER</div>
                  <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:8}}>
                    {qubits.map((q,i)=>{
                      const col=q===0?"#818cf8":q===1?"#00ffcc":"#f97316";
                      return(
                        <div key={i} style={{textAlign:"center"}}>
                          <div style={{
                            width:44,height:44,margin:"0 auto 4px",borderRadius:"50%",
                            border:`2px solid ${col}`,background:col+"11",
                            display:"flex",alignItems:"center",justifyContent:"center",
                            fontSize:9,fontWeight:700,color:col,
                            boxShadow:`0 0 10px ${col}44`,
                            animation:(phase>=1&&phase<=3)||(patchPhase>=1&&patchPhase<=3)?"pulse 1.1s infinite":"none",
                            animationDelay:i*0.08+"s",
                          }}>
                            {q===0?"⟨ψ⟩":q===1?"|1⟩":"|0⟩"}
                          </div>
                          <div style={{fontSize:8,color:"#3a6055"}}>q{i}</div>
                        </div>
                      );
                    })}
                  </div>
                  <div style={{display:"flex",gap:12,marginTop:12,fontSize:9,flexWrap:"wrap"}}>
                    <span><span style={{color:"#818cf8"}}>⟨ψ⟩</span> Superposition</span>
                    <span><span style={{color:"#00ffcc"}}>|1⟩</span> High</span>
                    <span><span style={{color:"#f97316"}}>|0⟩</span> Low</span>
                  </div>
                </div>

                {/* Hamiltonian */}
                <div className="card" style={{background:"#040d14",padding:16}}>
                  <div style={{fontSize:8,color:"#3a6055",letterSpacing:3,marginBottom:14}}>HAMILTONIAN COMPONENTS</div>
                  {[
                    {label:"H_problem (Cost)",val:Math.min(1,(progress/100)*0.9),col:"#f97316"},
                    {label:"H_driver (Transverse)",val:Math.max(0,1-(progress/100)*0.9),col:"#38bdf8"},
                    {label:"H_mixer (QAOA)",val:0.4+Math.sin((progress/100)*Math.PI)*0.4,col:"#818cf8"},
                    {label:"H_walk (Graph)",val:Math.min(1,(progress/100)*1.1),col:"#f472b6"},
                  ].map(h=>(
                    <div key={h.label} style={{marginBottom:12}}>
                      <div style={{display:"flex",justifyContent:"space-between",fontSize:9,marginBottom:4}}>
                        <span style={{color:"#b8d4cc"}}>{h.label}</span>
                        <span style={{color:h.col,fontWeight:700}}>{h.val.toFixed(4)}</span>
                      </div>
                      <div style={{height:4,background:"#0a1520",borderRadius:2}}>
                        <div style={{height:"100%",width:(h.val*100)+"%",background:h.col,borderRadius:2,transition:"width .5s"}}/>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Energy convergence */}
              <div className="card" style={{background:"#040d14",padding:16}}>
                <div style={{fontSize:8,color:"#3a6055",letterSpacing:3,marginBottom:10}}>ENERGY CONVERGENCE HISTORY</div>
                <div style={{height:80}}>
                  <MiniSparkline data={energyHist} color="#00ffcc" h={80}/>
                </div>
                <div style={{display:"flex",justifyContent:"space-between",fontSize:8,color:"#3a6055",marginTop:4}}>
                  <span>Initial state (high energy)</span><span>→</span><span>Global minimum</span>
                </div>
              </div>

              {/* Node risk heatmap */}
              <div className="card" style={{background:"#040d14",padding:16}}>
                <div style={{fontSize:8,color:"#3a6055",letterSpacing:3,marginBottom:12}}>NODE RISK SCORES</div>
                <div style={{display:"flex",flexDirection:"column",gap:6}}>
                  {[...GRAPH_NODES].sort((a,b)=>b.risk-a.risk).map(n=>(
                    <div key={n.id} className="node-row">
                      <span style={{fontSize:9,color:NODE_COLORS[n.type],width:80,flexShrink:0}}>{n.label}</span>
                      <div style={{flex:1,height:6,background:"#0a1520",borderRadius:3}}>
                        <div style={{
                          height:"100%",width:(n.risk*100)+"%",borderRadius:3,transition:"width .5s",
                          background:n.risk>0.75?"linear-gradient(90deg,#f97316,#ff3366)":
                                     n.risk>0.5 ?"linear-gradient(90deg,#eab308,#f97316)":
                                                   "linear-gradient(90deg,#00ffcc,#38bdf8)",
                        }}/>
                      </div>
                      <span style={{fontSize:9,width:32,textAlign:"right",color:n.risk>0.75?"#f97316":n.risk>0.5?"#eab308":"#00ffcc",flexShrink:0}}>
                        {(n.risk*100).toFixed(0)}%
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ══ LOG TAB ══ */}
          {activeTab==="log"&&(
            <div className="card fadeIn" style={{background:"#020810",padding:16,height:"calc(100vh - 185px)"}}>
              <div style={{fontSize:8,color:"#3a6055",letterSpacing:3,marginBottom:10}}>REAL-TIME EVENT LOG</div>
              <div ref={logRef} style={{height:"calc(100% - 28px)",overflowY:"auto",display:"flex",flexDirection:"column",gap:2}}>
                {log.length===0&&<div style={{color:"#3a6055",fontSize:11}}>Waiting for operations...</div>}
                {log.map((entry,i)=>{
                  const cols={system:"#38bdf8",quantum:"#818cf8",super:"#f472b6",score:"#f5a623",phase:"#00ffcc",success:"#00ffaa",error:"#ff4466",info:"#5a8a7a"};
                  return(
                    <div key={i} style={{fontSize:10,color:cols[entry.type]||"#5a8a7a",lineHeight:1.5,display:"flex",gap:8}}>
                      <span style={{color:"#1a3a2a",flexShrink:0}}>
                        {new Date(entry.ts).toLocaleTimeString("en",{hour12:false,hour:"2-digit",minute:"2-digit",second:"2-digit"})}
                      </span>
                      <span>{entry.msg}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
