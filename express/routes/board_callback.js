const express = require('express');

const router = express.Router(); // express의 router 기능을 쓰겠다
const mongoClient = require('./mongo');

const { MongoClient, ServerApiVersion, MinKey } = require('mongodb');

const uri =
  'mongodb+srv://lkf6214:f19940501@cluster0.etnufua.mongodb.net/?retryWrites=true&w=majority';

// callback !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
router.get('/', async (req, res) => {
  // 글 전체 목록 보여주기
  MongoClient.connect(uri, (err, db) => {
    const data = db.db('kdt1').collection('board');

    // data(kdt1)에서 전체 데이터를 받아와서 toArray
    data.find({}).toArray((err, result) => {
      const ARTICLE = result;
      const articleCounts = ARTICLE.length;
      res.render('board', { articleCounts, ARTICLE });
    });
  });
});

router.get('/write', (req, res) => {
  // 글 쓰기 모드로 이동
  res.render('board_write');
});

router.post('/write', (req, res) => {
  // 글 추가 기능 수행

  // required 처리를 front 에서 해줬기 때문에 사실 예외처리 안해줘도 된다..?
  if (req.body.title && req.body.content) {
    const newArticle = {
      title: req.body.title,
      content: req.body.content,
    };

    MongoClient.connect(uri, (err, db) => {
      const data = db.db('kdt1').collection('board');
      data.insertOne(newArticle, (err, result) => {
        res.redirect('/board');
      });
    });
  } else {
    const err = new Error('데이터가 없습니다');
    err.statusCode = 404;
    throw err;
  }
});

router.get('/modify/title/:title', (req, res) => {
  // 글 수정 모드로 이동
  MongoClient.connect(uri, (err, db) => {
    const data = db.db('kdt1').collection('board');
    data.findOne({ title: req.params.title }, (err, result) => {
      if (err) {
        throw err;
      } else {
        const selectedArticle = result;
        res.render('board_modify', { selectedArticle });
      }
    });
  });
});

router.post('/modify/title/:title', (req, res) => {
  // 글 수정 기능 수행
  if (req.body.title && req.body.content) {
    MongoClient.connect(uri, (err, db) => {
      const data = db.db('kdt1').collection('board');
      data.updateOne(
        { title: req.params.title },
        {
          $set: {
            title: req.body.title,
            content: req.body.content,
          },
        },
        (err, result) => {
          if (err) {
            throw err;
          } else {
            res.redirect('/board');
          }
        }
      );
    });
  } else {
    const err = new Error('요청 값이 없습니다.');
    err.statusCode = 404;
    throw err;
  }
});

router.delete('/delete/title/:title', async (req, res) => {
  MongoClient.connect(uri, (err, db) => {
    const data = db.db('kdt1').collection('board');
    data.deleteOne({ title: req.params.title }, (err, result) => {
      if (err) {
        throw err;
      } else {
        res.send('삭제 완료');
      }
    });
  });
});

module.exports = router;
