function pad(number, length) {
    number = number.toString();

    while (number.length < length) {
        number = "0" + number;
    }
    
    return number;
}

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

function validateInput(clockId, port, secret) {
    if (!clockId) {
        throw "Please enter a clock ID";
    }

    try {
        parsedClockId = BigInt("0x" + clockId)
    } catch {
        throw "Clock ID must be a hexadecimal number";
    }

    if (parsedClockId <= 0n) {
        throw "Clock ID must be greater than 0";
    }

    if (parsedClockId >= 0xffffffffffffffffn) {
        throw "Clock ID must be smaller than 2^64 - 1";
    }

    if (!port) {
        throw "Please enter a port";
    }

    try {
        parsedPort = BigInt("0x" + port)
    } catch {
        throw "Port must be a hexadecimal number";
    }

    if (parsedPort <= 0n) {
        throw "Port must be greater than 0";
    }

    if (parsedPort >= 0xffffn) {
        throw "Port must be smaller than 2^16 - 1";
    }

    if (secret && secret.match(/[0-9]+/) == null) {
        throw "Secret must only contain numeric characters";
    }
}

function getClocks() {
    const message = JSON.stringify({task: "get_clocks", length: 10});
    sendMessage(message);
}

function inspectClock() {
    const clockId = document.getElementById("inspectClockId").value;
    const port = document.getElementById("inspectPort").value;
    const secret = document.getElementById("inspectSecret").value;

    try {
        validateInput(clockId, port, null)
    } catch (e) {
        notifyError(e);
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
    const time = document.getElementById("createTime").value;
    const date = document.getElementById("createDate").value;
    const userDescription = btoa(document.getElementById("createUserDescription").value);
    const authenticationPolicy = document.getElementById("createAuthenticationPolicy").value;
    const visible = document.getElementById("createVisible").value == "visible";
    const secret = document.getElementById("createSecret").value;

    try {
        validateInput(clockId, port, secret)
    } catch (e) {
        notifyError(e);
        return;
    }

    if (!time || !date) {
        var offset = 0;
    } else {
        const dateTime = new Date(date + "T" + time + "Z");

        if (dateTime.getTime() < 0 || dateTime.getTime() > (2 ** 63) / 1000000) {
            notifyError("Start time/date out of range");
            return;
        }

        var offset = dateTime.getTime() * 1000000;
    }

    const message = JSON.stringify({task: "create_clock", clockId: clockId, port: port, offset: offset, visible: visible, authenticationPolicy: authenticationPolicy, userDescription: userDescription, secret: secret});
    sendMessage(message);
}

function handleResponseGetClocks(response) {
    const table = document.getElementById("clockTable");
    table.innerHTML = "";

    for (const [key, port] of Object.entries(response.ports)) {
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

        const dateTime = new Date(port.time * 1000);

        const tdDate = document.createElement("td");
        tdDate.textContent = pad(dateTime.getUTCDate(), 2) + "." + pad(dateTime.getUTCMonth() + 1, 2) + "." + dateTime.getUTCFullYear();
        row.appendChild(tdDate);

        const tdTime = document.createElement("td");
        tdTime.textContent = pad(dateTime.getUTCHours(), 2) + ":" + pad(dateTime.getUTCMinutes(), 2) + ":" + pad(dateTime.getUTCSeconds(), 2);
        row.appendChild(tdTime);

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

    const binaryUserDescription = new Uint8Array([...atob(response.userDescription)].map(char => char.charCodeAt(0)));

    addRow("User description", new TextDecoder('utf-8').decode(binaryUserDescription));

    if (response.authenticationPolicy == "none") {
        addRow("Authentication policy", "None (unsecured)");
    } if (response.authenticationPolicy == "plain") {
        addRow("Authentication policy", "Plaintext (legacy)");
    } else if (response.authenticationPolicy == "hmac") {
        addRow("Authentication policy", "HMAC");
    }
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

function sendMessage(message) {
    fetch("/api", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: message
    })
    .then(res => res.json())
    .then(handleResponse)
    .catch(err => notifyError("Error communicating with server: " + err));
}

function updateClocks() {
    const table = document.getElementById("clockTable");

    for (const row of table.childNodes) {
        columns = row.childNodes

        const tdDate = columns[1]
        const tdTime = columns[2]

        const date = columns[1].innerText
        const time = columns[2].innerText

        let dateTime = new Date();
        dateTime.setUTCFullYear(date.split(".")[2])
        dateTime.setUTCMonth(date.split(".")[1] - 1)
        dateTime.setUTCDate(date.split(".")[0])
        dateTime.setUTCHours(time.split(":")[0])
        dateTime.setUTCMinutes(time.split(":")[1])
        dateTime.setUTCSeconds(time.split(":")[2])

        dateTime = new Date(dateTime.getTime() + 1000)

        tdDate.textContent = pad(dateTime.getUTCDate(), 2) + "." + pad(dateTime.getUTCMonth() + 1, 2) + "." + dateTime.getUTCFullYear();
        tdTime.textContent = pad(dateTime.getUTCHours(), 2) + ":" + pad(dateTime.getUTCMinutes(), 2) + ":" + pad(dateTime.getUTCSeconds(), 2);
    }
}

function updateSecret(event) {
    const secret = document.getElementById("createSecret");
    const authenticationPolicy = document.getElementById("createAuthenticationPolicy");

    if (authenticationPolicy.value == "none") {
        secret.style.display = "none";
    } else {
        secret.style.display = "inherit";
    }
}

window.onload = () => {
    getClocks();

    setInterval(updateClocks, 1000);
};
