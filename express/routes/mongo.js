// @ts-check

const { MongoClient, ServerApiVersion } = require('mongodb');

const uri = process.env.DB_URI_LOCAL;
const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverApi: ServerApiVersion.v1,
});

module.exports = client;

//   const db = await client.connect();
//   console.log(db);
//   await client.close();
// async function main() {
//   await client.connect();
//   // 서버 접속
//   const users = client.db('kdt1').collection('users');
//   // 유저 라는 컬렉션을 만듦
//   //   await users.deleteMany({});
//   // ({}) 조건을 넣는것, 비어있으면 조건 없이 지워라 라는 뜻. 그리고 그 안에 다 넣는다

//   await users.deleteMany({
//     age: { $gte: 5 },
//   });
//   //5살 미만은 지워라

//   await users.updateMany(
//     {
//       age: { $gte: 5 },
//     },
//     {
//       $set: {
//         old: 'yes',
//       },
//     }
//   );
//   //5살 이상인 애를 찾아서 필드값에 old는 yes다 라고 넣기

//   //   users.deleteOne({
//   //     name: 'crong',
//   //     });
//   // 하나만 지우는거

//   //   await users.insertOne({
//   //     name: 'pororo',
//   //     age: 5,
//   //   });
//   //   // 하나만 추가하는 거

//   await users.insertMany([
//     {
//       name: 'pororo',
//       age: 5,
//     },
//     {
//       name: 'loopy',
//       age: 6,
//     },
//     {
//       name: 'crong',
//       age: 4,
//     },
//   ]);
//   //   //여러개 넣는거 배열에 넣어야함.

//   //   users.deleteOne({
//   //     name: 'crong',
//   //   });

//   //   const data = users.find({
//   //     name: 'loopy',
//   //   });
//   //   console.log(data);
//   //   await data.forEach(console.log);

//   //   await users.updateMany(
//   //     {
//   //       age: { $gte: 5 },
//   //     },
//   //     {
//   //       $set: {
//   //         name: '5살 이상',
//   //       },
//   //     }
//   //   );
//   // 5살 이상일 떼 '5살이상'이라고 입력하기

//   const data = users.find({
//     $and: [{ age: { $gte: 5 } }, { name: 'loopy' }],
//   });
//   await data.forEach(console.log);
//   //5살 이상이면서 이름이 loopy인 애를 찾아라

//   //   const data = users.find({});
//   // 이름이 tetz 인 사람/ 나이가 n을 찾아주세요
//   //   await data.forEach(console.log);
//   //   //   데이터에 있는 값을 하나하나 넣어서 출력하겠다, 배열의 foreach랑 다른거임

//   //   const arr = await data.toArray();
//   //   console.log(arr);
//   //   console.log(data);
//   await client.close();
// }

// main();
