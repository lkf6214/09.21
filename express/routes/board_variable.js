// @ts-check

const express = require('express');

const router = express.Router();

const ARTICLE = [
  {
    title: 'title',
    content:
      'Lorem ipsum, dolor sit amet consectetur adipisicing elit. Quia delectus iustofugiat autem cupiditate adipisci quas, in consectetur repudiandae, soluta, suscipitdebitis veniam nobis aspernatur blanditiis ex ipsum tempore impedit.',
  },
  {
    title: 'title2',
    content:
      'Lorem ipsum, dolor sit amet consectetur adipisicing elit. Quia delectus iustofugiat autem cupiditate adipisci quas, in consectetur repudiandae, soluta, suscipitdebitis veniam nobis aspernatur blanditiis ex ipsum tempore impedit.',
  },
];

router.get('/', (req, res) => {
  // res.write('<h1>Welcome</h1>');
  // 글 전체 목록 보여주기
  const articleLen = ARTICLE.length;
  res.render('board', { ARTICLE, articleCounts: articleLen });
  // 특정 뷰파일을 그려라, 파일명'board' 써주고 {key값을 오브젝트에 담아서}
});

router.get('/write', (req, res) => {
  // 글 쓰기 모드로 이동
  res.render('board_write');
  // 'board_write'를 그려줘
});

router.post('/write', (req, res) => {
  // 글 추가 기능 수행
  if (req.body.title && req.body.content) {
    // 하나라도 null이면 error 둘다 있으면 newArticle
    const newArticle = {
      title: req.body.title,
      content: req.body.content,
    };
    ARTICLE.push(newArticle);
    // 새롭게 만든글을 push 하겠다
    res.redirect('/board');
    // 그리고 전체 글을 보여주는 이 주소로 보내주세요
  } else {
    const err = new Error('데이터가 없습니다.');
    err.statusCode = 404;
    throw err;
  }
});

router.get('/modify/title/:title', (req, res) => {
  // 글 수정 모드로 이동
  const arrIndex = ARTICLE.findIndex(
    (article) => article.title === req.params.title
  );
  const selectedArticle = ARTICLE[arrIndex];
  res.render('board_modify', { selectedArticle });
});

router.post('/modify/title/:title', (req, res) => {
  // 글 수정 기능 수행
  if (req.body.title && req.body.content) {
    const arrIndex = ARTICLE.findIndex(
      (article) => article.title === req.params.title
    );
    // 화살표함수 뒤에 중괄호 없으면 return하라는 것
    if (arrIndex !== -1) {
      ARTICLE[arrIndex].title = req.body.title;
      ARTICLE[arrIndex].content = req.body.content;
      res.redirect('/board');
      // redirect안하면 hang걸려있음
    } else {
      const err = new Error('요청 값이 없습니다.');
      err.statusCode = 404;
      throw err;
    }
  } else {
    const err = new Error('요청 쿼리 이상');
    err.statusCode = 404;
    throw err;
  }
});

router.delete('/delete/title/:title', (req, res) => {
  // 글 삭제 기능 수행
  const arrIndex = ARTICLE.findIndex(
    (article) => article.title === req.params.title
  );
  if (arrIndex !== -1) {
    // -1 찾았을 떄
    ARTICLE.splice(arrIndex, 1);
    res.send('삭제 완료');
    // redirect 쓰면 안됨 send 써야함
  } else {
    // 못찾았을 떄
    const err = new Error('해당 제목을 가진 글이 없습니다!');
    err.statusCode = 404;
    throw err;
  }
});

module.exports = router;
