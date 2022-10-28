// 0919 월

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const NaverStrategy = require('passport-naver').Strategy;

const mongoClient = require('./mongo');

module.exports = () => {
  passport.use(
    new LocalStrategy(
      {
        usernameField: 'id',
        passwordField: 'password',
      },

      // 실제 로그인 기능 구현 부분
      async (id, password, cb) => {
        // 서버에 유저 정보를 전달하여 id 가 있는지 확인
        const client = await mongoClient.connect();
        const userCursor = client.db('kdt1').collection('user');
        const idResult = await userCursor.findOne({ id });
        // id가 존재하면 비밀번호 까지 있는지 확인하기
        if (idResult !== null) {
          if (idResult.password === password) {
            cb(null, idResult);
          } else {
            // 각각 상황에 맞는 에러 메세지 전달
            cb(null, false, { message: '비밀번호가 틀렸습니다.' });
          }
        } else {
          cb(null, false, { message: '해당 id 가 없습니다.' });
          console.log(idResult);
        }
      }
    )
  );

  passport.use(
    new NaverStrategy(
      {
        clientID: process.env.NAVER_CLIENT,
        clientSecret: process.env.NAVER_CLIENT_SECRET,
        callbackURL: process.env.NAVER_CB_URL,
      },
      // 실제 로그인 기능 구현 부분
      async (accessToken, refreshToken, profile, cb) => {
        console.log(profile);
        cb(null, profile);
        const client = await mongoClient.connect();
        const userCursor = client.db('kdt1').collection('users');
        const result = await userCursor.findOne({ id: profile.id });
        if (result !== null) {
          cb(null, result);
        } else {
          const newNaverUser = {
            id: profile.id,
            name:
              profile.displayName !== undefined
                ? profile.displayName
                : profile.emails[0].value,
            provider: profile.provider,
          };
          const dbResult = await userCursor.insertOne(newNaverUser);
          if (dbResult.acknowledged) {
            cb(null, newNaverUser);
          } else {
            cb(null, false, { message: 'NAVER 회원 생성 에러' });
          }
        }
      }
    )
  );

  passport.serializeUser((user, cb) => {
    cb(null, user.id);
  });

  passport.deserializeUser(async (id, cb) => {
    const client = await mongoClient.connect();
    const userCursor = client.db('kdt1').collection('user');
    const result = await userCursor.findOne({ id });
    if (result !== null) cb(null, result);
  });
};
