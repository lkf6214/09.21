// @ts-check

const express = require('express');

const router = express.Router();

const POST = [
  {
    title: 'me',
    content: '이지현',
  },
  {
    title: 'dad',
    content: '이용운',
  },
  {
    title: 'mom',
    content: '김인숙',
  },
  {
    title: 'sister',
    content: '이명희',
  },
];

router.get('/', (req, res) => {
  const postsLen = POST.length;
  res.render('posts', { POST, postsCounts: postsLen, imgName: 'potato.jpg' });
});

router.get('/:title', (req, res) => {
  const postData = POST.find((post) => post.title === req.params.title);
  if (postData) {
    res.send(postData);
  } else {
    const err = new Error('ID not found.');
    err.statusCode = 404;
    throw err;
  }
});

router.post('/', (req, res) => {
  if (Object.keys(req.query).length >= 1) {
    if (req.query.title && req.query.content) {
      const newPost = {
        title: req.query.title,
        content: req.query.content,
      };
      POST.push(newPost);
      res.send('포스팅 완료');
    } else {
      const err = new Error('Unexpected query');
      err.statusCode = 404;
      throw err;
    }
  } else if (req.body) {
    if (req.query.title && req.query.content) {
      const newPost = {
        title: req.query.title,
        content: req.query.content,
      };
      POST.push(newPost);
      res.redirect('/posts');
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

// 포스팅 수정!! put거의안쓰고 post쓰긴하지만 배우는중이니까 put 쓸 것
router.put('/:title', (req, res) => {
  if (req.query.title && req.query.content) {
    // 아이디어가 있는지 네임이 있는지 여부에 따라 처리
    const postData = POST.find((post) => post.title === req.params.title);
    if (postData) {
      const arrIndex = POST.findIndex(
        (post) => post.title === req.params.title
      );
      const modifyPost = {
        title: req.query.title,
        content: req.query.content,
      };
      POST[arrIndex] = modifyPost;
      res.send('포스팅 수정 완료');
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

// 글 삭제!!
router.delete('/:title', (req, res) => {
  const arrIndex = POST.findIndex((post) => post.title === req.params.title);
  if (arrIndex !== -1) {
    POST.splice(arrIndex, arrIndex + 1);
    res.send('해당 포스팅이 삭제되었습니다..');
  } else {
    const err = new Error('ID not found.');
    err.statusCode = 404;
    throw err;
  }
});

module.exports = router;
