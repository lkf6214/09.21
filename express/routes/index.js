// @ts-check

const express = require('express');

const router = express.Router();

router.get('/', (req, res) => {
  // cookie 이름이 alert인 것
  console.log(req.cookies.popup);
  res.render('index', { popup: req.cookies.popup });
});

router.post('/cookie', (req, res) => {
  res.cookie('popup', 'hide', {
    // 쿠키 옵션값 써주기
    expires: new Date(Date.now() + 1000 * 60 * 60 * 24), // 현재 시간 받아오는 .now 이용
    httpOnly: true, // 통신이 일어날 때만 읽을 수 있게 하는 옵션
    // 통신중이 아닐때는 접근하지 못하도록(보안)
  });
  res.send('cookie생성성공');
});

// 모듈 밖으로 빼기
module.exports = router;
