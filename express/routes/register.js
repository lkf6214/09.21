// @ts-check
//  회원가입 기능을 모듈화

const express = require('express');

// crypto 암호화
const crypto = require('crypto');

const router = express.Router();
const mongoClient = require('./mongo');

const createHashedPassword = (password) => {
  const salt = crypto.randomBytes(64).toString('base64');
  const hashedPassword = crypto
    .pbkdf2Sync(password, salt, 10, 64, 'sha512')
    .toString('base64');
  return { hashedPassword, salt };
  // 해싱할 값, salt, 해시 함수 반복 횟수, 해시 값 길이, 해시 알고리즘
};

const verifyPassword = (password, salt, userPassword) => {
  const hashed = crypto
    .pbkdf2Sync(password, salt, 10, 64, 'sha512')
    .toString('base64');
  console.log('hashed', hashed);
  console.log('userpw', userPassword);

  if (hashed === userPassword) return true;
  return false;
};

router.get('/', (req, res) => {
  // console.log(creatHashedPassword('1234'));
  // console.log(verifyPassword('1234', salt, userPw));
  res.render('register');
});

router.post('/', async (req, res) => {
  // db접속부터
  const client = await mongoClient.connect();
  const userCursor = client.db('kdt1').collection('user');
  const duplicated = await userCursor.findOne({ id: req.body.id });
  console.log(duplicated);

  // 실질적인 회원가입 부분
  const PasswordResult = createHashedPassword(req.body.password);

  if (duplicated === null) {
    const result = await userCursor.insertOne({
      id: req.body.id,
      name: req.body.id,
      password: PasswordResult.hashedPassword,
      salt: PasswordResult.salt,
    });
    if (result.acknowledged) {
      res.status(200);
      res.send('회원 가입 성공!<br><a href="/login">로그인 페이지로 이동</a>');
    } else {
      res.status(500);
      res.send(
        '회원 가입 문제 발생.<br><a href="/register">회원가입 페이지로 이동</a>'
      );
    }
  } else {
    res.status(300);
    res.send(
      '중복된 id 가 존재합니다.<br><a href="/register">회원가입 페이지로 이동</a>'
    );
  }
});

// './' = 이미 연결되어있으니까 localhost:4000/register 이라는 뜻
module.exports = { router, verifyPassword };
