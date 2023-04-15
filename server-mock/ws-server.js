const WebSocketServer = require('ws').Server;

const wss = new WebSocketServer({port: 9000});
const clients = [];

function handleConnection(client, request) {
    console.log("New Connection");
    clients.push(client);

    function endClient() {
        const position = clients.indexOf(client);
        clients.splice(position, 1);
        console.log("connection closed");
    }

    function clientResponse(data) {
        console.log(request.connection.remoteAddress + ': ' + data);
        broadcast(request.connection.remoteAddress + ': ' + data);
    }

    client.on('message', clientResponse);
    client.on('close', endClient);
}

function broadcast(data) {
    for (let c in clients) {
        clients[c].send(JSON.stringify(data));
    }
}

wss.on('connection', handleConnection);
