/*
 * cognito-srp-browser.js v0.0.1
 * A JavaScript library for SRP in browser for Amazon Cognito.
 * https://github.com/nobrin/cognito-srp-browser
 * Copyright (c) 2020 Nobuo Okazaki
 * MIT Licensed.
 *
 * Depends browser native BigInt and Crypto.subtle
 * - BigInt: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt
 * - Crypto.subtle: https://developer.mozilla.org/en-US/docs/Web/API/Crypto/subtle
 *
 * Code example:
	const USERPOOL_ID = "ap-northeast-1_EXAMPLEXX";
	const ID_POOL = "ap-northeast-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
	const CLIENT_ID = "userpoolappclientidxxxxxxx";
	const REGION = USERPOOL_ID.split("_")[0];
	const PROVIDER_COGNITO = `cognito-idp.${REGION}.amazonaws.com/${USERPOOL_ID}`;

	// Initially Unauthenticated User
	AWS.config.region = REGION;
	AWS.config.credentials = new AWS.CognitoIdentityCredentials({IdentityPoolId: ID_POOL});

	async function signIn(username, password) {
		const idp = new AWS.CognitoIdentityServiceProvider();
		const srp = new CognitoSRP(username, password, USERPOOL_ID, CLIENT_ID);
		await srp.init();	// Initialize CognitoSRP

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
 */

const CognitoSRP = function() {
	// https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L22
	const N_hex
		= 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' + '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
		+ 'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' + 'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
		+ 'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' + 'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'
		+ '83655D23DCA3AD961C62F356208552BB9ED529077096966D' + '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
		+ 'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' + 'DE2BCBF6955817183995497CEA956AE515D2261898FA0510'
		+ '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' + 'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7'
		+ 'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' + 'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C'
		+ 'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' + '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF';

	// https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L49
	const g_hex = "2";

	function hexToUint8Array(hexstr) {
		// Convert hex string to Uint8Array
		if(hexstr.length % 2){ hexstr = "0" + hexstr; }
		const a = new Uint8Array(hexstr.length / 2);
		for(let i=0; i<hexstr.length;i+=2){
			a[i / 2] = parseInt(hexstr.slice(i, i + 2), 16);
		}
		return a;
	}

	function bufferToHex(buffer) {
		// Convert ArrayBuffer to hex string
		const a = new Uint8Array(buffer);
		let s = "";
		for(let i=0;i<a.byteLength;i++){
			let c = a[i].toString(16);
			s += (c.length % 2 ? "0" : "") + c
		}
		return s;
	}

	function expmod(base, exp, mod){
		// Modular exponentiation for BigInt
		// https://stackoverflow.com/questions/5989429/pow-and-mod-function-optimization/5989549
		if(exp == 0n){ return 1n; }
		if(exp % 2n == 0n){ return expmod(base, (exp / 2n), mod) ** 2n % mod; }
		return (base * expmod(base, (exp - 1n), mod)) % mod;
	}

	function hexToLong(hexstr) { return BigInt("0x" + hexstr); }
	function longToHex(bn) { return bn.toString(16); }

	function padHex(hexstr) {
		if(hexstr.length % 2){ hexstr = "0" + hexstr; }
		else if("89ABCDEFabcdef".indexOf(hexstr[0]) >= 0){ hexstr = "00" + hexstr; }
		return hexstr;
	}

	function getRandomHex(bytes) {
		function getRandomInt(max) { return Math.floor(Math.random() * Math.floor(max)); }
		let s = "";
		for(let n=0;n<bytes;n++){
			let c = getRandomInt(256).toString(16);
			s += (c.length % 2 ? "0" : "") + c;
		}
		return s;
	}

	async function hexHash(hexstr) { return await sha256hex(hexToUint8Array(hexstr).buffer); }
	async function sha256hex(buf) { return bufferToHex(await crypto.subtle.digest("SHA-256", buf)); }
	async function hashSha256(text) { return await sha256hex(new TextEncoder().encode(text)); }

	async function hmac(keystr, msg) {
		const key = await crypto.subtle.importKey("raw", keystr, {name: "HMAC", hash: "SHA-256"}, true, ["sign"]);
		return new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));
	}

	const INFO_BITS = "Caldera Derived Key";
	class CognitoSRP {
		constructor(username, password, userpoolId, clientId) {
			this.username = username;
			this.password = password;
			this.userpoolId = userpoolId;	// "ap-northeast-1_Abcd12345"
			this.clientId = clientId;		// Application client ID of Cognito Userpool

			this.big_n = BigInt("0x" + N_hex);
			this.g = BigInt("0x" + g_hex);
		}

		async init(small_a_value) {
			// Initialize
			this.k = hexToLong(await hexHash("00" + N_hex + "0" + g_hex));
			this.small_a_value = small_a_value || hexToLong(getRandomHex(128)) % this.big_n;
			this.large_a_value = expmod(this.g, this.small_a_value, this.big_n);
		}

		getAuthParameters() {
			// AuthParameters for initiateAuth()
			return {
				USERNAME: this.username,
				SRP_A: this.large_a_value.toString(16)
			};
		}

		async _calculate_u(big_a, big_b) {
			const u_hex_hash = await hexHash(padHex(longToHex(big_a)) + padHex(longToHex(big_b)));
			return hexToLong(u_hex_hash);
		}

		async _compute_hkdf(ikm, salt) {
			const prk = await hmac(salt, ikm);
			const info_bits_update = INFO_BITS + String.fromCharCode(1);
			const hmac_hash = await hmac(prk, new TextEncoder().encode(info_bits_update));
			return hmac_hash.slice(0, 16);
		}

		async getPasswordAuthenticationKey(username, password, srp_b_value, salt) {
			const u_value = await this._calculate_u(this.large_a_value, srp_b_value);
			const username_password = this.userpoolId.split("_")[1] + this.username + ":" + this.password;
			const username_password_hash = await hashSha256(username_password);

			const x_value = hexToLong(await hexHash(padHex(salt) + username_password_hash));
			const g_mod_pow_xn = expmod(this.g, x_value, this.big_n);
			const int_value2 = srp_b_value - this.k * g_mod_pow_xn;
			let s_value = expmod(int_value2, this.small_a_value + u_value * x_value, this.big_n);
			if(s_value < 0n){ s_value += this.big_n; } // If s_value is negative, add big_n to be positive.
			return await this._compute_hkdf(hexToUint8Array(padHex(longToHex(s_value))), hexToUint8Array(padHex(longToHex(u_value))));
		}

		async processChallenge(challenge_params) {
			const user_id_for_srp = challenge_params.USER_ID_FOR_SRP;
			const salt_hex = challenge_params.SALT;
			const srp_b_hex = challenge_params.SRP_B;
			const secret_block_b64 = challenge_params.SECRET_BLOCK;

			const dt = new Date();
			const ts = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][dt.getUTCDay()]
				+ " " + ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][dt.getUTCMonth()]
				+ " " + dt.getUTCDate() + " " + dt.toUTCString().split(" ")[4] + " UTC " + dt.getUTCFullYear();
			const hkdf = await this.getPasswordAuthenticationKey(user_id_for_srp, this.password, hexToLong(srp_b_hex), salt_hex);
			const secret_block_bytes = atob(secret_block_b64);

			const msg = this.userpoolId.split("_")[1] + user_id_for_srp + secret_block_bytes + ts;
			let a = new Uint8Array(msg.length);
			for(let i=0;i<msg.length;i++){ a[i] = msg[i].charCodeAt(); }
			const hmac_obj = await hmac(hkdf, a);
			let buf = "";
			for(let i=0;i<hmac_obj.byteLength;i++){ buf += String.fromCharCode(hmac_obj[i]); }
			const signature_string = btoa(buf);

			return {
				TIMESTAMP: ts,
				USERNAME: user_id_for_srp,
				PASSWORD_CLAIM_SECRET_BLOCK: secret_block_b64,
				PASSWORD_CLAIM_SIGNATURE: signature_string
			};
		}
	}
	return CognitoSRP;
}();
