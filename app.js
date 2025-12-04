// ==========================================
// 1. NAVIGATION (SIDEBAR SWITCHING)
// ==========================================

var btnNavUser = document.getElementById("nav-user");
var btnNavAdmin = document.getElementById("nav-admin");
var viewUser = document.getElementById("view-user");
var viewAdmin = document.getElementById("view-admin");

// Switch to User View
btnNavUser.onclick = function() {
    btnNavUser.classList.add("active");
    btnNavAdmin.classList.remove("active");
    
    viewUser.classList.add("active");
    viewUser.classList.remove("hidden");
    
    viewAdmin.classList.remove("active");
    viewAdmin.classList.add("hidden");
};

// Switch to Admin View
btnNavAdmin.onclick = function() {
    btnNavAdmin.classList.add("active");
    btnNavUser.classList.remove("active");
    
    viewAdmin.classList.add("active");
    viewAdmin.classList.remove("hidden");
    
    viewUser.classList.remove("active");
    viewUser.classList.add("hidden");
};

// ==========================================
// 2. BACKEND CONNECTION
// ==========================================

var baseUrlInput = document.getElementById("base-url");
var saveBtn = document.getElementById("btn-save-url");
var myUrl = "https://credential-generator-with-policy-controls.onrender.com"; // Default

saveBtn.onclick = function() {
    myUrl = baseUrlInput.value;
    alert("URL Saved: " + myUrl);
};

// ==========================================
// 3. USER PANEL: CREATE CREDENTIAL
// ==========================================

var createBtn = document.querySelector("#form-create button"); 
var createOutput = document.getElementById("result-create");

createBtn.onclick = async function(e) {
    e.preventDefault();

    // 1. Get values from form
    var p = document.getElementById("principal").value;
    var s = document.getElementById("scopes").value;
    var t = document.getElementById("ttl").value;
    var l = document.getElementById("len").value;

    var data = {
        principal: p,
        scopes: s.split(","), 
        ttl_seconds: Number(t),
        length: Number(l)
    };

    try {
        // 2. Send request
        var response = await fetch(myUrl + "/credentials", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });

        var json = await response.json();

        // 3. Handle Errors (like Quota Exceeded)
        if (!response.ok) {
            createOutput.innerHTML = `<div style="color:red; font-weight:bold;">Error: ${json.detail}</div>`;
            createOutput.style.display = "block";
            return;
        }

        // 4. Handle Pending (Approval Needed)
        if (json.status === "pending") {
            createOutput.innerHTML = `
                <div style="background:#fff7ed; border-left:4px solid #f97316; padding:12px; color:#9a3412;">
                    <strong>⏳ Approval Required!</strong><br>
                    Your request ID is below. Copy this to check your status later:<br><br>
                    <div style="background:white; padding:8px; border:1px solid #fdba74; font-family:monospace; font-weight:bold;">
                        ${json.request_id}
                    </div>
                </div>
            `;
        } 
        // 5. Handle Issued (Success)
        else if (json.status === "issued") {
            createOutput.innerHTML = `
                <div style="background:#f0fdf4; border-left:4px solid #4ade80; padding:12px; color:#166534;">
                    <strong>✅ Success!</strong><br>
                    Here is your new API Secret:<br><br>
                    <div style="background:#14532d; color:#4ade80; padding:10px; font-family:monospace; border-radius:4px;">
                        ${json.secret}
                    </div>
                </div>
            `;
        }

        createOutput.style.display = "block";

    } catch (err) {
        createOutput.innerText = "Error connecting to server. Is it running?";
        createOutput.style.display = "block";
    }
};

// ==========================================
// 4. USER PANEL: CHECK STATUS (Claim Key)
// ==========================================

var checkBtn = document.querySelector("#form-check button");
var checkOutput = document.getElementById("result-check");

checkBtn.onclick = async function(e) {
    e.preventDefault();
    var id = document.getElementById("check-id").value;

    try {
        //  Fetch the full list to find our ID
        var responseList = await fetch(myUrl + "/credentials");
        var dataList = await responseList.json();
        
        var myRequest = null;
        
        // Find ID in list
        for(var i=0; i<dataList.length; i++) {
            if(dataList[i].id === id) {
                myRequest = dataList[i];
                break;
            }
        }

        if (!myRequest) {
            checkOutput.innerHTML = "❌ ID not found in system.";
            checkOutput.style.display = "block";
            return;
        }

        //  Show status or fetch secret
        if (myRequest.status === "pending") {
            checkOutput.innerHTML = "⏳ <b>Status: Pending</b><br>Please ask an Admin to approve this request.";
            checkOutput.style.display = "block";
        } 
        else if (myRequest.status === "revoked") {
            checkOutput.innerHTML = "🚫 <b>Status: Revoked</b><br>This key has been disabled.";
            checkOutput.style.display = "block";
        }
        else if (myRequest.status === "active") {
            // It's active! Fetch the secret using debug endpoint
            var responseDebug = await fetch(myUrl + "/_debug/decrypt/" + id);
            var jsonDebug = await responseDebug.json();
            
            checkOutput.innerHTML = "✅ <b>APPROVED!</b><br>Here is your API Key:<br><br>" + 
                                    "<div style='background:#111; color:#4ade80; padding:10px; border-radius:4px; font-family:monospace;'>" + 
                                    jsonDebug.secret_plaintext + 
                                    "</div>";
            checkOutput.style.display = "block";
        }

    } catch (err) {
        checkOutput.innerText = "Error checking status.";
        checkOutput.style.display = "block";
    }
};

// ==========================================
// 5. ADMIN PANEL: LIST CREDENTIALS
// ==========================================

var listBtn = document.getElementById("btn-list");
var listOutput = document.getElementById("result-list");
var clearListBtn = document.getElementById("btn-list-clear");

clearListBtn.onclick = function() {
    listOutput.innerHTML = "<div class='empty-state'>List cleared. Click Refresh.</div>";
};

listBtn.onclick = async function() {
    try {
        var response = await fetch(myUrl + "/credentials");
        var data = await response.json();

        var html = "<table><thead><tr><th>ID</th><th>User</th><th>Status</th></tr></thead><tbody>";

        for(var i = 0; i < data.length; i++) {
            var item = data[i];
            
            var statusColor = item.status === 'active' ? 'green' : (item.status === 'revoked' ? 'red' : 'orange');

            html += "<tr>";
            html += "<td style='font-family:monospace; color:#6b7280; font-size:0.85em'>" + item.id + "</td>";
            html += "<td>" + item.principal + "</td>";
            html += "<td style='color:" + statusColor + "; font-weight:bold'>" + item.status + "</td>";
            html += "</tr>";
        }

        html += "</tbody></table>";
        listOutput.innerHTML = html;
    } catch (err) {
        listOutput.innerHTML = "Error loading list.";
    }
};

// ==========================================
// 6. ADMIN PANEL: ACTIONS
// ==========================================

// --- APPROVE ---
var approveBtn = document.querySelector("#form-approve button");
var approveOutput = document.getElementById("result-approve");

approveBtn.onclick = async function(e) {
    e.preventDefault();
    var id = document.getElementById("approve-id").value;

    try {
        var response = await fetch(myUrl + "/requests/" + id + "/approve", {
            method: "POST"
        });
        var json = await response.json();
        
        if(!response.ok) {
             approveOutput.innerText = "Error: " + json.detail;
        } else {
             approveOutput.innerText = "Approved! Key Generated.";
        }
        approveOutput.style.display = "block";
    } catch(err) {
        approveOutput.innerText = "Failed to connect.";
        approveOutput.style.display = "block";
    }
};

// --- REVOKE ---
var revokeBtn = document.querySelector("#form-revoke button");
var revokeOutput = document.getElementById("result-revoke");

revokeBtn.onclick = async function(e) {
    e.preventDefault();
    var id = document.getElementById("revoke-id").value;

    try {
        var response = await fetch(myUrl + "/credentials/" + id + "/revoke", {
            method: "POST"
        });
        var json = await response.json();
        
        if(!response.ok) {
             revokeOutput.innerText = "Error: " + json.detail;
        } else {
             revokeOutput.innerText = "Credential Revoked.";
        }
        revokeOutput.style.display = "block";
    } catch(err) {
        revokeOutput.innerText = "Failed to connect.";
        revokeOutput.style.display = "block";
    }
};

// --- DEBUG ---
var debugBtn = document.querySelector("#form-debug button");
var debugOutput = document.getElementById("result-debug");

debugBtn.onclick = async function(e) {
    e.preventDefault();
    var id = document.getElementById("debug-id").value;

    try {
        var response = await fetch(myUrl + "/_debug/decrypt/" + id);
        var json = await response.json();
        
        if(!response.ok) {
            debugOutput.innerText = "Error: " + json.detail;
        } else {
            debugOutput.innerText = "Secret: " + json.secret_plaintext;
        }
        debugOutput.style.display = "block";
    } catch(err) {
        debugOutput.innerText = "Failed to connect.";
        debugOutput.style.display = "block";
    }
};