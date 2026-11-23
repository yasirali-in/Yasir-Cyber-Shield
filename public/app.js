const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const pageNames = {overview:"Overview","file-scan":"File Scanner","url-check":"URL Checker","ip-check":"IP Lookup",courses:"Cybersecurity Course",quiz:"Knowledge Quiz",resources:"Security Resources"};
function showPage(name){
  $$(".page").forEach(p=>p.classList.toggle("active",p.id===`page-${name}`));
  $$(".nav-link").forEach(b=>b.classList.toggle("active",b.dataset.page===name));
  $("#crumb").textContent=pageNames[name]||"Overview";
  $("#sidebar").classList.remove("open");
  window.scrollTo({top:0,behavior:"smooth"});
}
document.addEventListener("click",e=>{const b=e.target.closest("[data-page]");if(b){e.preventDefault();showPage(b.dataset.page)}});
$("#mobileMenu").addEventListener("click",()=>$("#sidebar").classList.toggle("open"));

const fileInput=$("#fileInput"), dropzone=$("#dropzone"), selected=$("#selectedFile"), consent=$("#consent"), scanButton=$("#scanButton");
let chosenFile=null;
function formatBytes(n){if(n<1024)return `${n} B`;if(n<1048576)return `${(n/1024).toFixed(1)} KB`;return `${(n/1048576).toFixed(2)} MB`}
function setFile(file){
  if(!file)return;
  if(file.size>32*1024*1024){alert("Maximum file size is 32 MB.");return}
  chosenFile=file;$("#fileName").textContent=file.name;$("#fileMeta").textContent=`${formatBytes(file.size)} · ${file.type||"Unknown type"}`;
  selected.hidden=false;dropzone.hidden=true;scanButton.disabled=!consent.checked;
}
fileInput.addEventListener("change",()=>setFile(fileInput.files[0]));
$("#removeFile").addEventListener("click",()=>{chosenFile=null;fileInput.value="";selected.hidden=true;dropzone.hidden=false;scanButton.disabled=true});
["dragenter","dragover"].forEach(ev=>dropzone.addEventListener(ev,e=>{e.preventDefault();dropzone.classList.add("dragover")}));
["dragleave","drop"].forEach(ev=>dropzone.addEventListener(ev,e=>{e.preventDefault();dropzone.classList.remove("dragover")}));
dropzone.addEventListener("drop",e=>setFile(e.dataTransfer.files[0]));
consent.addEventListener("change",()=>scanButton.disabled=!(chosenFile&&consent.checked));

function renderStats(stats){
 return `<div class="result-grid">${[["Malicious",stats.malicious||0],["Suspicious",stats.suspicious||0],["Harmless",stats.harmless||0],["Undetected",stats.undetected||0]].map(([n,v])=>`<div class="metric"><b>${v}</b><small>${n.toUpperCase()}</small></div>`).join("")}</div>`;
}
function safe(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
scanButton.addEventListener("click",async()=>{
 if(!chosenFile||!consent.checked)return;
 scanButton.disabled=true;scanButton.textContent="Analyzing…";
 const result=$("#scanResult");result.hidden=false;result.innerHTML="<p class='muted'>Processing file securely. Please wait…</p>";
 try{
  const form=new FormData();form.append("file",chosenFile);
  const r=await fetch("/api/scan-file",{method:"POST",body:form});const d=await r.json();if(!r.ok)throw new Error(d.error||"Scan failed");
  if(d.mode==="demo"){
   result.innerHTML=`<div class="result-title"><h3>File details</h3><span class="tiny-count">DEMO MODE</span></div><p class="muted">Local metadata analysis completed.</p><div class="result-grid"><div class="metric"><b>${formatBytes(d.fileSize)}</b><small>FILE SIZE</small></div><div class="metric"><b>SHA-256</b><small>HASH ALGORITHM</small></div></div><p class="micro-note"><b>${safe(d.fileName)}</b> · ${safe(d.mimeType)}</p><div class="hash-box">${safe(d.sha256)}</div><p class="warning-text">⚠ ${safe(d.message)}</p>`;
  }else{
   result.innerHTML=`<div class="result-title"><h3>VirusTotal analysis</h3><span class="tiny-count">SUBMITTED</span></div><p class="muted">${safe(d.fileName)} · ${formatBytes(d.fileSize)}</p><div id="vtStatus" class="inline-result">Waiting for analysis results…</div><div class="hash-box">SHA-256: ${safe(d.sha256)}</div>`;
   pollAnalysis(d.analysisId);
  }
 }catch(e){result.innerHTML=`<p class="warning-text">${safe(e.message)}</p>`}
 finally{scanButton.disabled=false;scanButton.innerHTML='Analyze file <span>→</span>'}
});
async function pollAnalysis(id){
 const box=$("#vtStatus");
 for(let i=0;i<8;i++){
  await new Promise(r=>setTimeout(r,2500));
  try{const r=await fetch(`/api/analysis/${encodeURIComponent(id)}`);const d=await r.json();if(!r.ok)throw new Error(d.error);
   if(d.status==="completed"){box.innerHTML=`<b>Analysis completed</b>${renderStats(d.stats)}<p class="micro-note">Detection counts are supplied by VirusTotal. Review individual engine results in the official report.</p>`;return}
   box.textContent=`Analysis status: ${d.status||"queued"} · checking again…`;
  }catch(e){box.textContent=e.message;return}
 }
 box.textContent="Analysis is still processing. Try again later using the analysis ID shown in the browser network response, or check VirusTotal directly.";
}
async function postJson(url,body,target,button){
 target.hidden=false;target.textContent="Checking…";button.disabled=true;
 try{const r=await fetch(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});const d=await r.json();if(!r.ok)throw new Error(d.error);
  if(d.mode==="demo"){target.innerHTML=`<b>Demo mode · ${safe(d.host||d.ip)}</b><br>${safe(d.message)}`}
  else target.innerHTML=`<b>Reputation report · ${safe(d.host||d.ip)}</b>${d.country?`<br>Country: ${safe(d.country)} · Network: ${safe(d.asOwner)}`:""}${renderStats(d.stats)}<p class="micro-note">Reputation data can be incomplete or outdated. Verify important findings.</p>`;
 }catch(e){target.textContent=e.message}finally{button.disabled=false}
}
$("#urlButton").addEventListener("click",()=>postJson("/api/scan-url",{url:$("#urlInput").value},$("#urlResult"),$("#urlButton")));
$("#ipButton").addEventListener("click",async()=>{
 const ip=$("#ipInput").value.trim();const target=$("#ipResult"),button=$("#ipButton");target.hidden=false;target.textContent="Looking up…";button.disabled=true;
 try{const r=await fetch(`/api/ip/${encodeURIComponent(ip)}`);const d=await r.json();if(!r.ok)throw new Error(d.error);
  target.innerHTML=d.mode==="demo"?`<b>Demo mode · ${safe(d.ip)}</b><br>${safe(d.message)}`:`<b>IP report · ${safe(d.ip)}</b><br>Country: ${safe(d.country)} · Network: ${safe(d.asOwner)}${renderStats(d.stats)}`;
 }catch(e){target.textContent=e.message}finally{button.disabled=false}
});

const modules=[
 ["Cybersecurity Fundamentals","Understand the CIA triad, security goals, risk and the role of a security professional.","Confidentiality means information is accessible only to authorized people. Integrity means information remains accurate and complete. Availability means systems and data are accessible when needed. Together these form the CIA triad. Learn the difference between an asset, a threat, a vulnerability and risk. A vulnerability is a weakness; a threat may exploit it; risk combines likelihood and impact."],
 ["Threats, Malware & Social Engineering","Recognize viruses, worms, trojans, ransomware, spyware and manipulation techniques.","Malware is software designed to harm, disrupt or gain unauthorized access. A virus attaches to a host file, a worm can spread independently, a trojan disguises itself as legitimate software, ransomware locks or encrypts data, and spyware secretly collects information. Social engineering manipulates people. Defenses include trusted downloads, backups, patching and user awareness."],
 ["Network Security","Learn IP addresses, ports, firewalls, DNS, VPNs and secure network practices.","An IP address identifies a device or interface on a network. Ports identify services. A firewall applies rules to network traffic. DNS translates domain names into IP addresses. HTTPS protects web traffic in transit using TLS. Secure networks use strong Wi-Fi encryption, updated router firmware, segmentation and least-privilege access."],
 ["Web Application Security","Explore authentication, authorization, input validation, sessions and common web risks.","Authentication verifies who a user is; authorization determines what they can do. Validate input on the server, encode output, use parameterized database queries, protect sessions and configure security headers. Study the OWASP Top 10 to understand common web application risks such as access control failures and injection."],
 ["Cryptography & Encryption","Understand hashing, symmetric encryption, asymmetric encryption and digital signatures.","Hashing creates a fixed-length digest and is designed to be one-way. SHA-256 is commonly used for integrity checks. Symmetric encryption uses one shared secret key. Asymmetric cryptography uses a public/private key pair. Digital signatures help verify authenticity and integrity. Never invent your own cryptographic algorithm; use trusted libraries and protocols."],
 ["Identity & Access Management","Study passwords, multi-factor authentication, roles and least privilege.","Use long, unique passwords stored in a password manager. Multi-factor authentication adds another proof of identity, such as an authenticator app or security key. Role-based access control assigns permissions according to job roles. Least privilege means granting only the access needed, for only as long as needed."],
 ["Incident Response & Digital Forensics","Learn how teams prepare for, detect, contain, eradicate and recover from incidents.","A basic incident response lifecycle includes preparation, detection and analysis, containment, eradication, recovery and lessons learned. Preserve evidence, record timestamps and actions, and avoid altering affected systems unnecessarily. Do not run suspicious files on your everyday computer. Use isolated, authorized lab environments."],
 ["Security Ethics & Safe Practice","Apply responsible disclosure, privacy, legal boundaries and safe lab behavior.","Only test systems when you have explicit permission and a clearly defined scope. Do not access, alter or disrupt other people's systems or data. Protect personal information, follow applicable laws and institutional policies, document your work, and report vulnerabilities responsibly to the authorized owner."]
];
$("#courseGrid").innerHTML=modules.map((m,i)=>`<article class="course-card"><div class="course-card-head"><span class="course-num">${String(i+1).padStart(2,"0")}</span><h3>${m[0]}</h3></div><p>${m[1]}</p><details><summary>Open lesson notes</summary><p class="lesson">${m[2]}</p></details></article>`).join("");

const questions=[
 ["What does the 'C' in the CIA triad stand for?",["Control","Confidentiality","Connectivity","Certification"],1,"Confidentiality ensures information is available only to authorized people."],
 ["Which malware commonly encrypts files and demands payment?",["Spyware","Adware","Ransomware","Worm"],2,"Ransomware encrypts or locks data and demands a ransom."],
 ["What does HTTPS primarily help protect?",["Data in transit","Screen brightness","Battery health","File size"],0,"HTTPS uses TLS to protect data exchanged between a browser and a website."],
 ["What is the purpose of a firewall?",["Create passwords","Filter network traffic","Compress files","Design websites"],1,"A firewall applies rules to allow or block network traffic."],
 ["Which is a cryptographic hash function?",["HTML","SHA-256","FTP","CSS"],1,"SHA-256 produces a 256-bit digest and is used for integrity checks."],
 ["What does MFA add to account security?",["More usernames","An additional verification factor","Public access","Faster internet"],1,"Multi-factor authentication requires more than one type of proof."],
 ["What should you do before security testing a website?",["Get explicit permission","Guess its password","Disable its services","Copy its data"],0,"Security testing must be authorized and stay within an agreed scope."],
 ["Which action helps reduce phishing risk?",["Open every attachment","Reuse one password","Verify sender and domain","Ignore browser warnings"],2,"Check the sender and domain carefully before clicking links or opening attachments."]
];
let qIndex=0,score=0,answered=false;
function renderQuestion(){
 const q=questions[qIndex];answered=false;$("#quizProgress").textContent=`QUESTION ${String(qIndex+1).padStart(2,"0")} / 08`;$("#quizScore").textContent=`Score: ${score}`;$("#progressBar").style.width=`${(qIndex+1)/questions.length*100}%`;$("#questionText").textContent=q[0];$("#answerFeedback").hidden=true;$("#nextQuestion").disabled=true;$("#nextQuestion").textContent=qIndex===questions.length-1?"Finish quiz →":"Next question →";
 $("#answers").innerHTML=q[1].map((a,i)=>`<button class="answer-option" data-answer="${i}">${String.fromCharCode(65+i)}. &nbsp; ${a}</button>`).join("");
 $$(".answer-option").forEach(b=>b.addEventListener("click",()=>{if(answered)return;answered=true;const chosen=Number(b.dataset.answer);if(chosen===q[2])score++;$$(".answer-option").forEach((x,i)=>{x.disabled=true;if(i===q[2])x.classList.add("correct");else if(i===chosen)x.classList.add("wrong")});$("#quizScore").textContent=`Score: ${score}`;$("#answerFeedback").hidden=false;$("#answerFeedback").textContent=(chosen===q[2]?"Correct! ":"Not quite. ")+q[3];$("#nextQuestion").disabled=false;}));
}
$("#nextQuestion").addEventListener("click",()=>{if(!answered)return;if(qIndex<questions.length-1){qIndex++;renderQuestion()}else{$("#questionText").textContent=`Quiz complete — you scored ${score} out of ${questions.length}.`;$("#answers").innerHTML="";$("#answerFeedback").hidden=false;$("#answerFeedback").textContent=score>=6?"Great work. Keep practicing and exploring the course modules.":"Good effort. Review the course modules and try again.";$("#nextQuestion").textContent="Restart quiz →";$("#nextQuestion").disabled=false;$("#nextQuestion").onclick=()=>{qIndex=0;score=0;$("#nextQuestion").onclick=null;renderQuestion()}}});
renderQuestion();
fetch("/api/status").then(r=>r.json()).then(d=>{const pill=$(".status-pill");pill.innerHTML=`<i></i> ${d.apiConfigured?"VirusTotal API connected":"Demo mode active"}`}).catch(()=>{});
