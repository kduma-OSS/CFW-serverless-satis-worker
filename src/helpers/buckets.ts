// https://www.designcise.com/web/tutorial/how-to-convert-javascript-readablestream-object-to-json
async function toJSON(body: ReadableStream<any>) {
	const reader = body.getReader(); // `ReadableStreamDefaultReader`
	const decoder = new TextDecoder();
	const chunks: string[] = [];

	async function read() {
		const { done, value } = await reader.read();

		// all chunks have been read?
		if (done) {
			return JSON.parse(chunks.join(''));
		}

		const chunk = decoder.decode(value, { stream: true });
		chunks.push(chunk);
		return read(); // read the next chunk
	}

	return read();
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url)
		let objectName = url.pathname.slice(1)

		console.log(`${request.method} object ${objectName}: ${request.url}`)

		if (request.method !== 'GET' && request.method !== 'HEAD') {
			return new Response(`Unsupported method`, {
				status: 400
			})
		}

		if (objectName === '') {
			objectName = 'index.html'
		}

		if (request.method === 'GET') {
			const object = await env.R2_BUCKET.get(objectName, {
				range: request.headers,
				onlyIf: request.headers,
			})

			if (object === null) {
				return this.objectNotFound(objectName)
			}

			const headers = new Headers()
			object.writeHttpMetadata(headers)
			headers.set('etag', object.httpEtag)
			if (object.range) {
				// @ts-ignore
				headers.set("content-range", `bytes ${object.range.offset}-${object.range.end ?? object.size - 1}/${object.size}`)
			}
			// @ts-ignore
			const status = object.body ? (request.headers.get("range") !== null ? 206 : 200) : 304

			// @ts-ignore
			return new Response(object.body, {
				headers,
				status
			})
		}

		const object = await env.R2_BUCKET.head(objectName)

		if (object === null) {
			return this.objectNotFound(objectName)
		}

		const headers = new Headers()
		object.writeHttpMetadata(headers)
		headers.set('etag', object.httpEtag)
		return new Response(null, {
			headers,
		})
	},
	objectNotFound(objectName: string)  {
		return new Response(`<html><body>Object "<b>${objectName}</b>" not found</body></html>`, {
			status: 404,
			headers: {
				'content-type': 'text/html; charset=UTF-8'
			}
		})
	},
	async getPermissions(pathname: string, env: Env): Promise<string[] | null> {
		let key = '.tags' + pathname + '.json';
		const object = await env.R2_BUCKET.get(key)

		if (object === null) {
			return null;
		}

		return await toJSON(object.body);
	}
};
