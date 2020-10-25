# CognitoでのSRP認証用モジュール
## 概要
Cognito User PoolでSRP(Secure Remote Password)プロトコルで認証するためのブラウザ用のJavaScriptモジュールです。
AWS Amplifyを使えば実現できますが、フレームワークを使わずに実現することができます。

## 使い方
AWS SDK for JavaScript in the Browserと使用します。
ブラウザネイティブのBigIntとCrypto.subtleを使っているので、対応しているブラウザが必要です。
動作確認はWindows10(1909)+Firefox 82.0(64bit)で行いました。

```HTML:signin.html
<!DOCTYPE html>
<html>
<head>
  <title>Cognito Test</title>
  <script src="https://sdk.amazonaws.com/js/aws-sdk-2.778.0.min.js"></script>
  <script src="cognito-srp-browser.js"></script>
</head>
<body>
  <h1>Cognito</h1>
  <script>
    const USERPOOL_ID = "ap-northeast-1_EXAMPLEXX";
    const ID_POOL = "ap-northeast-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
    const CLIENT_ID = "userpoolappclientidxx";
    const REGION = USERPOOL_ID.split("_")[0]
    const PROVIDER_COGNITO = `cognito-idp.${REGION}.amazonaws.com/${USERPOOL_ID}`;

    // Initially Unauthenticated User
    AWS.config.region = REGION;
    AWS.config.credentials = new AWS.CognitoIdentityCredentials({IdentityPoolId: ID_POOL});

    async function signIn(username, password) {
      const idp = new AWS.CognitoIdentityServiceProvider();
      const srp = new CognitoSRP(username, password, USERPOOL_ID, CLIENT_ID);
      await srp.init();

      return new Promise((resolve, reject) => {
        // Initiate auth
        const p1 = {
          AuthFlow: "USER_SRP_AUTH",
          ClientId: CLIENT_ID,
          AuthParameters: srp.getAuthParameters()
        };
        idp.initiateAuth(p1, async (err, data) => {
          // Respond to auth challenge
          const p2 = {
            ClientId: CLIENT_ID,
            ChallengeName: data.ChallengeName,  // PASSWORD_VERIFIER
            ChallengeResponses: await srp.processChallenge(data.ChallengeParameters)
          };
          idp.respondToAuthChallenge(p2, (err, data) => {
            console.debug(err);
            console.debug(data);

            if(data && data.AuthenticationResult && data.AuthenticationResult.IdToken){
              // Switching Unauthenticated Users to Authenticated Users
              // https://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/loading-browser-credentials-cognito.html
              AWS.config.credentials.params.Logins = AWS.config.credentials.params.Logins || {};
              AWS.config.credentials.params.Logins[PROVIDER_COGNITO] = data.AuthenticationResult.IdToken;
              resolve(data);  // Resolve promise
            }else{
              reject(err);    // Reject
            }
          });
        });
      });
    }

    signIn("username", "password")
    .then(res => {
      const s3 = new AWS.S3();
      const p = {Bucket: "mybucket", Key: "myfile.txt"};
      s3.getObject(p, (err, data) => {
        console.debug(err);
        console.debug(data);
      });
    });
  </script>
</body>
</html>
```

## 詳細
CognitoSRPオブジェクトを作成し、初期化後、CognitoIdentityServiceProviderで認証することができます。

### 初期化

```js
// オブジェクトを生成し、初期化する
const srp = new CognitoSRP(username, password, userpoolId, clientId);
await srp.init();
```

### 認証の初期化パラメータを生成する

```js
// initiateAuthのパラメータを生成する
const param = {
    AuthFlow: "USER_SRP_AUTH",
    ClientId: clientId,
    AuthParameters: srp.getAuthParameters()
};
```

### パスワード認証コードを生成する

```js
// initiateAuth()で得られたChallengeParametersを元に認証コードを生成する
const param = {
    ClientId: CLIENT_ID,
    ChallengeName: data.ChallengeName,  // PASSWORD_VERIFIER
    ChallengeResponses: await srp.processChallenge(data.ChallengeParameters)
};
```

### IDフェデレーション
Cognito User Poolで認証して得られたIdTokenをCognito IDプールに渡すことでIDフェデレーションを利用することができます。

```js
// Switching Unauthenticated Users to Authenticated Users
// https://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/loading-browser-credentials-cognito.html
AWS.config.credentials.params.Logins = AWS.config.credentials.params.Logins || {};
AWS.config.credentials.params.Logins[PROVIDER_COGNITO] = data.AuthenticationResult.IdToken;
```

## 参考サイト
- warrant-lite
  - https://github.com/capless/warrant-lite
  - SRPの実装はほとんどこれを参考にしました。
- BigInt (MDN)
  - https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt
- Crypto.subtle (MDN)
  - https://developer.mozilla.org/en-US/docs/Web/API/Crypto/subtle
- Amazon Cognito ID を使用してユーザーを認証する
  - https://docs.aws.amazon.com/ja_jp/sdk-for-javascript/v2/developer-guide/loading-browser-credentials-cognito.html
- Secure Remote Password protocol (Wikipedia)
  - https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol  
