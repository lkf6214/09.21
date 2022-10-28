// @ ts-check

const express = require('express');
// 익스프레스 모듈 쓴다는 말

const router = express.Router();

const USER = [
  {
    id: 'me',
    name: '이지현',
    email: 'lkf6214@naver.com',
  },
  {
    id: 'dad',
    name: '이용운',
    email: 'test@naver.com',
  },
  {
    id: 'mom',
    name: '김인숙',
    email: 'test@naver.com',
  },
  {
    id: 'sister',
    name: '이명희',
    email: 'test@naver.com',
  },
];

router.get('/', (req, res) => {
  const userLen = USER.length;
  res.render('users', { USER, userCounts: userLen, imgName: 'potato.jpg' });
});

// userRouter.get('/', (req, res) => {
//   res.write('<h1>hello, Dynamic Web page</h1>');
//   for (let i = 0; i < USER.length; i++) {
//     res.write(`<h2>USER id is ${USER[i].id}`);
//     res.write(`<h2>USER name is ${USER[i].name}`);
//   }
//   // res.send(USER);
// });

router.get('/:id', (req, res) => {
  const userData = USER.find((user) => user.id === req.params.id);
  if (userData) {
    res.send(userData);
  } else {
    const err = new Error('ID not found.');
    err.statusCode = 404;
    throw err;
  }
});

router.post('/', (req, res) => {
  if (Object.keys(req.query).length >= 1) {
    if (req.query.id && req.query.name && req.query.email) {
      const newUser = {
        id: req.query.id,
        name: req.query.name,
        email: req.query.email,
      };
      USER.push(newUser);
      res.send('회원 등록 완료');
    } else {
      const err = new Error('Unexpected query');
      err.statusCode = 404;
      throw err;
    }
  } else if (req.body) {
    if (req.body.id && req.body.name && req.body.email) {
      const newUser = {
        id: req.body.id,
        name: req.body.name,
        email: req.query.email,
      };
      USER.push(newUser);
      res.redirect('/users');
    } else {
      const err = new Error('Unexpected query');
      err.statusCode = 404;
      throw err;
    }
  } else {
    const err = new Error('No data');
    err.statusCode = 404;
    throw err;
  }
});

// 회원 정보 수정!!미들웨어 완성 put거의안쓰고 post쓰긴하지만 배우는중이니까 put 쓸 것
router.put('/:id', (req, res) => {
  if (req.query.id && req.query.name && req.query.email) {
    // 아이디어가 있는지 네임이 있는지 여부에 따라 처리
    const userData = USER.find((user) => user.id === req.params.id);
    if (userData) {
      const arrIndex = USER.findIndex((user) => user.id === req.params.id);
      const modifyUser = {
        id: req.query.id,
        name: req.query.name,
        email: req.query.email,
      };
      USER[arrIndex] = modifyUser;
      res.send('회원 수정 완료');
    } else {
      const err = new Error('ID not found.');
      err.statusCode = 404;
      throw err;
    }
  } else {
    const err = new Error('unexpected Qeury');
    err.statusCode = 404;
    throw err;
  }
});

// 회원정보삭제!!
router.delete('/:id', (req, res) => {
  const arrIndex = USER.findIndex((user) => user.id === req.params.id);
  if (arrIndex !== -1) {
    USER.splice(arrIndex, arrIndex + 1);
    res.send('해당id의 정보가 삭제되었습니다..');
  } else {
    const err = new Error('ID not found.');
    err.statusCode = 404;
    throw err;
  }
});

module.exports = router;
