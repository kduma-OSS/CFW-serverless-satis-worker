import authHelper, { UserType } from './helpers/auth';
import bucketsHelper from './helpers/buckets';

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
		let user: UserType | null = null;

		let authorizationRequired = true;
		if(env.PUBLIC_ACCESS_TO_INDEX && (url.pathname == '/' || url.pathname == '/index.html')) {
			authorizationRequired = false;
		}

		if(env.PUBLIC_ACCESS_TO_JSON && (url.pathname == '/packages.json' || url.pathname.startsWith('/p2/') || url.pathname.startsWith('/include/'))) {
			authorizationRequired = false;
		}


		if(authorizationRequired) {
			let ba = await authHelper.basicAuth(request, env, ctx)
			if (ba instanceof Response) {
				return ba;
			}

			user = ba;
		}

		if(url.pathname.startsWith('/.checksums/') || url.pathname.startsWith('/.tags/')) {
			return authHelper.getForbiddenResponse();
		}

		if(env.CHECK_FILE_RESTRICTIONS && url.pathname.startsWith('/dist/')) {
			let permissions = await bucketsHelper.getPermissions(url.pathname, env);

			if(!permissions) {
				return authHelper.getForbiddenResponse();
			}

			if(user === null) {
				return authHelper.getForbiddenResponse();
			}

			// @ts-ignore
			let commonPermissions = permissions.filter((p: string) => user.permissions.includes(p));
			if(commonPermissions.length == 0) {
				return authHelper.getForbiddenResponse();
			}
		}

		return bucketsHelper.fetch(request, env);
	},
};
