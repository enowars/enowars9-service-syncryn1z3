let ws;
let current_page_index;

function notifySuccess(message) {
    const notificationBar = document.getElementById("notification-bar");

    notificationBar.innerText = message;
    notificationBar.className = "success";
}

function notifyError(message) {
    const notificationBar = document.getElementById("notification-bar");

    notificationBar.innerText = message;
    notificationBar.className = "error";
}

function getPage(page_index) {
    current_page_index = page_index;

    const message = JSON.stringify({task: "get_page", page_index: page_index, page_length: 10});
    sendMessage(message);
}

function claimPort() {
    const clockId = document.getElementById("claimClockId").value;
    const port = document.getElementById("claimPort").value;
    const userDescription = document.getElementById("claimUserDescription").value;
    const secret = document.getElementById("claimSecret").value;

    if (!clockId || !port) {
        notifyError("Please enter both clock ID and port");
        return;
    }

    const message = JSON.stringify({ task: "claim_port", clockId: clockId, port: port, authenticationPolicy: "hmac128", userDescription: userDescription, secret: secret});
    sendMessage(message);
}

function handleResponseGetPage(response) {
    const table = document.getElementById("portTable");
    table.innerHTML = "";

    for (const port of response.ports) {
        const row = document.createElement("tr");
        row.addEventListener("click", (event) => {
            const inputClockId = document.getElementById("inspectClockId");
            const inputPort = document.getElementById("inspectPort");

            inputClockId.value = row.childNodes[0].textContent;
            inputPort.value = row.childNodes[1].textContent;
        }); 

        const tdClockId = document.createElement("td");
        tdClockId.textContent = port.clockId;
        row.appendChild(tdClockId);

        const tdPort = document.createElement("td");
        tdPort.textContent = port.port;
        row.appendChild(tdPort);

        const tdAuth = document.createElement("td");
        tdAuth.textContent = port.authentication_policy;
        row.appendChild(tdAuth);

        const tdNotes = document.createElement("td");
        tdNotes.textContent = "";
        row.appendChild(tdNotes);

        table.appendChild(row);
    }
}

function handleResponseClaimPort(response) {
    const box = document.getElementById("claim-box");
    box.style.borderColor = "#4AB456";

    box.querySelectorAll("input").forEach(input => {
        input.value = "";
    });

    notifySuccess("Claimed port");

    getPage(current_page_index);
}

function handleResponse(response) {
    if (response.task == "get_page") {
        handleResponseGetPage(response);
    } if (response.task == "claim_port") {
        handleResponseClaimPort(response);
    } else if (Object.hasOwn(response, "error")) {
        notifyError("Received error from server: " + response.error);
    } else {

    }
}

function openConnection(openAction) {
    if (ws) {
        return
    }

    ws = new WebSocket("/ws/", "syncryn1z3");
    
    if (openAction) {
        ws.onopen = openAction;
    }

    ws.onmessage = (event) => {
        handleResponse(JSON.parse(event.data));
    };

    ws.onerror = (error) => {
        console.error("WebSocket error:", error);
    };

    ws.onclose = () => {
        ws = null;
    };
}

function sendMessage(message) {
    send = () => {
        ws.send(message);
    };

    if (ws && ws.readyState === WebSocket.OPEN) {
        send();
    } else {
        openConnection(send);
    }
}

window.onload = () => {
    openConnection(() => {getPage(0);});
};
