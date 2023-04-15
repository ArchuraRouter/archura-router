const {createServer} = require('http');
const fs = require('fs');

const server = createServer(function (req, res) {
    console.log(req.url);
    console.log(req.headers);
    res.writeHead(200, {'Content-Type': 'text/html'});
    res.write(new Date().toString());
    res.end();
});

server.listen(9020);
