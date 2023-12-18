interface Env {
	AUTH: KVNamespace;

	R2_BUCKET: R2Bucket;

	PUBLIC_ACCESS_TO_INDEX: boolean;
	PUBLIC_ACCESS_TO_JSON: boolean;
	CHECK_FILE_RESTRICTIONS: boolean;
	STORE_PASSWORDS_HASHED: boolean;
	ENABLE_USER_ENDPOINT: boolean;
}
