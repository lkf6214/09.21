const express = require('express');

const router = express.Router();
const WebSocketServer = require('ws').Server;

const wss = new WebSocketServer({ port: 7777 });

wss.on('connection', (ws) => {
  wss.clients.forEach((client) => {
    client.send(`새로운 유저가 접속 했습니다. 현재 유저 ${wss.clients.size}`);
  });

  ws.on('message', (message) => {
    console.log(message.toString());
    wss.clients.forEach((client) => {
      client.send(message.toString());
    });
  });
  ws.on('close', () => {
    wss.clients.forEach((client) => {
      client.send(
        `유저 한명이 떠났습니다. 현재 유저 수는 ${wss.clients.size} 명`
      );
    });
  });
});
router.get('/', (req, res) => {
  res.render('chat');
});

router.get('/', (req, res) => {
  res.render('chat');
});
module.exports = router;
