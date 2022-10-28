// @ts-check

const express = require('express');

const cookieParser = require('cookie-parser');
const session = require('express-session');
const passport = require('passport');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT;

// body parser
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
// 쿠키파서
app.use(cookieParser('lkf'));

// Session
app.use(
  session({
    secret: 'lkf',
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60,
    },
  })
);

// passport
app.use(passport.initialize());
app.use(passport.session());

const router = require('./routes');
const boardsRouter = require('./routes/board');
const registerRouter = require('./routes/register');
const loginRouter = require('./routes/login');
const passportRouter = require('./routes/passport');
const chatRouter = require('./routes/chat');

passportRouter();

// // const postsRouter = express.Router();

app.set('view engine', 'ejs');
app.set('views', 'views');
// 프론트 파일
app.use('/uploads', express.static('uploads'));
app.use(express.static('public'));
// uploads 파일이 들어오면 uploads폴더에서 찾아라

app.use('/', router);
// 'localhost:4000/이 숨어있는 것'
// app.use('/users', userRouter);
// // userRouter부를 땐 이 주소 /users로 가져오겠다
// app.use('/posts', postsRouter);
// // 게시판 필요하면 위에 두개 다시 주석 제거하기
app.use('/board', boardsRouter);
app.use('/register', registerRouter.router);
app.use('/login', loginRouter.router);
app.use('/chat', chatRouter);

// 꼭 서버실행(listen) 바로 위에 있어야함. =맨 밑에 있어야함
app.use((err, req, res, next) => {
  console.log(err.stack);
  res.status(err.statusCode || 500);
  res.end(err.message);
});

app.listen(PORT, () => {
  console.log(`The express server is running at ${PORT}`);
  // console.log(`http://localhost:${PORT}`);
});
