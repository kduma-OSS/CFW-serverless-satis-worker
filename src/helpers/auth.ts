const encoder = new TextEncoder();

function getUnauthorizedResponse() {
	return new Response('Unauthorized - You need to login', {
		status: 401,
		statusText: 'Unauthorized - You need to login',
		headers: {
			"WWW-Authenticate": 'Basic realm="Authenticate to Satis repository", charset="UTF-8"',
		},
	});
}

function getMalformedAuthHeader() {
	return new Response("Malformed authorization header.", {
		status: 400,
	});
}

function getForbiddenResponse() {
	return new Response('Forbidden', {
		status: 403,
		statusText: 'Forbidden',
	});
}

/**
 * Protect against timing attacks by safely comparing values using `timingSafeEqual`.
 * Refer to https://developers.cloudflare.com/workers/runtime-apis/web-crypto/#timingsafeequal for more details
 */
function timingSafeEqual(a: string, b: string): boolean {
	const aBytes = encoder.encode(a);
	const bBytes = encoder.encode(b);

	if (aBytes.byteLength !== bBytes.byteLength) {
		// Strings must be the same length in order to compare
		// with crypto.subtle.timingSafeEqual
		return false;
	}

	return crypto.subtle.timingSafeEqual(aBytes, bBytes);
}

async function getUserFormStore(username: string, password: string, env: Env): Promise<UserType | false> {
	const storedUserDetails = await env.AUTH.get(username);

	if (!storedUserDetails) {
		return false;
	}

	let [storedPassword, permissions] = storedUserDetails.split("\n");

	if (!username || !password) {
		return false;
	}

	if(env.STORE_PASSWORDS_HASHED) {
		const myDigest = await crypto.subtle.digest("SHA-256", encoder.encode(password));
		const hash= Array.from(new Uint8Array(myDigest));
		password = hash.map(b => b.toString(16).padStart(2, '0')).join('');
	}

	if (!timingSafeEqual(storedPassword, password)) {
		return false;
	}

	let permissionsList = permissions ? permissions.split(",") : []
	return {
		username,
		permissions: permissionsList,
	};
}


export type UserType = { username: string, permissions: string[] };

export default {
	async basicAuth(request: Request, env: Env, ctx: ExecutionContext) {
		const authorization = request.headers.get("Authorization");

		if (!authorization) {
			return getUnauthorizedResponse();
		}

		const [scheme, encoded] = authorization.split(" ");

		// The Authorization header must start with Basic, followed by a space.
		if (!encoded || scheme !== "Basic") {
			return getMalformedAuthHeader();
		}

		const credentials = atob(encoded);
		const index = credentials.indexOf(":");
		const username = credentials.substring(0, index);
		const password = credentials.substring(index + 1);

		return await getUserFormStore(username, password, env) || getUnauthorizedResponse();
	},

	getUnauthorizedResponse() {
		return getUnauthorizedResponse();
	},

	getForbiddenResponse () {
		return getForbiddenResponse();
	},

	getLogOutResponse () {
		// Invalidate the "Authorization" header by returning a HTTP 401.
		// We do not send a "WWW-Authenticate" header, as this would trigger
		// a popup in the browser, immediately asking for credentials again.
		return new Response("Logged out.", { status: 401 });
	}
};
