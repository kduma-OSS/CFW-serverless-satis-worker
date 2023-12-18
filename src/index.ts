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

		if(env.ENABLE_USER_ENDPOINT && url.pathname == '/user.json') {
			return new Response(JSON.stringify(user, null, 2), {
				headers: {
					'content-type': 'application/json',
				},
			});
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

			let hasAccess = user.permissions.includes('*');
			permissions.forEach((p: string) => {
				// @ts-ignore
				if(user.permissions.includes(p)) {
					hasAccess = true;
				}
			});

			if (!hasAccess) {
				user.permissions.forEach((p: string) => {
					if(!p.includes('*')) {
						return;
					}

					let pattern = '^' + p.replace('*', '.*') + '$';

					// @ts-ignore
					permissions.forEach((p: string) => {
						// @ts-ignore
						if(p.match(pattern)) {
							hasAccess = true;
						}
					});

				});
			}

			if(!hasAccess) {
				return authHelper.getForbiddenResponse();
			}
		}

		if(env.CHECK_EXTRA_JSON_RESTRICTIONS && url.pathname.startsWith('/p2/') && url.pathname.endsWith('.json')) {
			let json: any = await bucketsHelper.loadJson(url.pathname, env);

			if(!json) {
				return bucketsHelper.objectNotFound(url.pathname);
			}

			Object.keys(json['packages']).forEach(function(key, index) {
				json['packages'][key] = json['packages'][key].map((version: any) => {
					if (!('extra' in version)) {
						return version;
					}

					if (!('s3-satis-file-restrictions' in version['extra'])) {
						return version;
					}

					if(user !== null) {
						let hasAccess = user.permissions.includes('*');
						version['extra']['s3-satis-file-restrictions'].forEach((p: string) => {
							// @ts-ignore
							if(user.permissions.includes(p)) {
								hasAccess = true;
							}
						});

						if (!hasAccess) {
							user.permissions.forEach((p: string) => {
								if(!p.includes('*')) {
									return;
								}
								let pattern = '^' + p.replace('*', '.*') + '$';
								// @ts-ignore
								version['extra']['s3-satis-file-restrictions'].forEach((p: string) => {
									// @ts-ignore
									if(p.match(pattern)) {
										hasAccess = true;
									}
								});
							});
						}

						if(!hasAccess) {
							return null;
						}
					}

					delete version['extra']['s3-satis-file-restrictions'];

					if(Object.keys(version['extra']).length == 0) {
						delete version['extra'];
					}

					return version;
				}).filter((version: any) => {
					return version !== null;
				});

				if(json['packages'][key].length == 0) {
					delete json['packages'][key];
				}
			});

			return new Response(JSON.stringify(json, null, 2), {
				headers: {
					'content-type': 'application/json',
				},
			});
		}

		return bucketsHelper.fetch(request, env);
	},
};
