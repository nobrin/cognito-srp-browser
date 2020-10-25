# SRP authentication module for Cognito in the browser

- JAPANESE document is available: See README_ja.md

## Synopsis
A implementation of SRP(Secure Remote Password protocol) for Cognito User Pool.  
Equivalent function has been implemented by the AWS Amplify. This module makes more simply to use the function.  
So you can use the module for small applications.

## Example
This module running with AWS SDK for JavaScript in the Browser.  
BigInt and Crypto.subtle that are implemented as browser native are used by the module. Supported browsers are required.

Operation check has been on Firefox 82.0(64bit) in Windows10(1909).

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

## Module details
Users can be authenticated by CognitoIdentityServiceProvider after the initializing of CognitoSRP object.

### Initialization

```js
// Instantiate a object and initialize
const srp = new CognitoSRP(username, password, userpoolId, clientId);
await srp.init();
```

### Generate parameters for initiateAuth()

```js
// AuthParameters for initiateAuth()
const param = {
    AuthFlow: "USER_SRP_AUTH",
    ClientId: clientId,
    AuthParameters: srp.getAuthParameters()
};
```

### Compute code for authentication

```js
// Compute code from ChallengeParameters from result of initiateAuth()
const param = {
    ClientId: CLIENT_ID,
    ChallengeName: data.ChallengeName,  // PASSWORD_VERIFIER
    ChallengeResponses: await srp.processChallenge(data.ChallengeParameters)
};
```

### ID Federation
ID Fedration can be used by IdToken obtained by authentication with Cognito User Pool.

```js
// Switching Unauthenticated Users to Authenticated Users
// https://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/loading-browser-credentials-cognito.html
AWS.config.credentials.params.Logins = AWS.config.credentials.params.Logins || {};
AWS.config.credentials.params.Logins[PROVIDER_COGNITO] = data.AuthenticationResult.IdToken;
```

## References
- warrant-lite
  - https://github.com/capless/warrant-lite
  - A python implementation of Cognito SRP
- BigInt (MDN)
  - https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt
- Crypto.subtle (MDN)
  - https://developer.mozilla.org/en-US/docs/Web/API/Crypto/subtle
- Using Amazon Cognito Identity to Authenticate Users
  - https://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/loading-browser-credentials-cognito.html
- Secure Remote Password protocol (Wikipedia)
  - https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol  
