let ws;

function notifySuccess(message) {
    const notificationBar = document.getElementById("notificationBar");

    notificationBar.innerText = message;
    notificationBar.className = "success";
}

function notifyError(message) {
    const notificationBar = document.getElementById("notificationBar");

    notificationBar.innerText = message;
    notificationBar.className = "error";
}

function getClocks() {
    const message = JSON.stringify({task: "get_clocks", length: 10});
    sendMessage(message);
}

function inspectClock() {
    const clockId = document.getElementById("inspectClockId").value;
    const port = document.getElementById("inspectPort").value;
    const secret = document.getElementById("inspectSecret").value;

    if (!clockId || !port) {
        notifyError("Please enter both clock ID and port");
        return;
    }

    const placeholder = document.getElementById("inspectPlaceholder");
    placeholder.style.display = "block";

    const list = document.getElementById("inspectList");
    list.style.display = "none";
    list.innerHTML = "";

    const message = JSON.stringify({ task: "inspect_clock", clockId: clockId, port: port, secret: secret});
    sendMessage(message);
}

function createClock() {
    const clockId = document.getElementById("createClockId").value;
    const port = document.getElementById("createPort").value;
    const userDescription = document.getElementById("createUserDescription").value;
    const authenticationPolicy = document.getElementById("createAuthenticationPolicy").value;
    const visible = document.getElementById("createVisible").value == "visible";
    const secret = document.getElementById("createSecret").value;

    if (!clockId || !port) {
        notifyError("Please enter both clock ID and port");
        return;
    }

    // TODO: support other auth methods
    const message = JSON.stringify({ task: "create_clock", clockId: clockId, port: port, visible: visible, authenticationPolicy: authenticationPolicy, userDescription: userDescription, secret: secret});
    sendMessage(message);
}

function handleResponseGetClocks(response) {
    const table = document.getElementById("clockTable");
    table.innerHTML = "";

    for (const port of response.ports) {
        const row = document.createElement("tr");
        row.addEventListener("click", (event) => {
            const inputClockId = document.getElementById("inspectClockId");
            const inputPort = document.getElementById("inspectPort");

            const port_id = row.childNodes[0].textContent.split("/");

            inputClockId.value = port_id[0];
            inputPort.value = port_id[1];
        }); 

        const tdPortId = document.createElement("td");
        tdPortId.textContent = port.clockId + "/" + port.port;
        row.appendChild(tdPortId);

        const tdCommand = document.createElement("td");
        const codeCommand = document.createElement("code");
        codeCommand.textContent = "python ptp_client.py " + window.location.hostname + " " + port.clockId + " " + port.port + " --secret [SECRET]" ;
        tdCommand.appendChild(codeCommand)
        row.appendChild(tdCommand);

        table.appendChild(row);
    }
}

function handleResponseInspectClock(response) {
    notifySuccess("Received clock info");

    const placeholder = document.getElementById("inspectPlaceholder");
    placeholder.style.display = "none";

    const list = document.getElementById("inspectList");
    list.style.display = "block";
    list.innerHTML = "";

    function addRow(title, value) {
        const row = document.createElement("div");
        row.className = "inspect-row";

        const label = document.createElement("div");
        label.className = "inspect-label";
        label.innerText = title;
        row.appendChild(label);

        const content = document.createElement("div");
        content.className = "inspect-content";
        content.innerText = value;
        row.appendChild(content);

        list.appendChild(row);
    }

    addRow("User description", response.userDescription);
    addRow("Authentication policy", (response.authenticationPolicy == "hmac") ? "HMAC" : "Plaintext (legacy)");
}

function handleResponseCreateClock(response) {
    const box = document.getElementById("create-box");

    box.querySelectorAll("input").forEach(input => {
        input.value = "";
    });

    notifySuccess("Created clock");

    getClocks();
}

function handleResponse(response) {
    if (response.task == "get_clocks") {
        handleResponseGetClocks(response);
    } else if (response.task == "inspect_clock") {
        handleResponseInspectClock(response);
    } else if (response.task == "create_clock") {
        handleResponseCreateClock(response);
    } else if (Object.hasOwn(response, "error")) {
        notifyError("Received error from server: " + response.error);
    } else {
        console.error("Received faulty response", response.toString());
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
    openConnection(getClocks());
};
