import { Google } from 'arctic';
import { dev } from '$app/environment';
import { env } from '$env/dynamic/private';

export function createGoogleAuth(requestUrl?: URL): Google {
	const clientId = env.GOOGLE_CLIENT_ID || '';
	const clientSecret = env.GOOGLE_CLIENT_SECRET || '';
	const redirectURI = (requestUrl && !dev)
		? `${requestUrl.origin}/login/google/callback`
		: (dev
			? 'http://localhost:5173/login/google/callback'
			: `${env.PUBLIC_APP_URL || env.APP_URL || 'http://localhost:5173'}/login/google/callback`);

	if (!clientId || !clientSecret) {
		throw new Error('Google OAuth credentials not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env');
	}

	return new Google(clientId, clientSecret, redirectURI);
}

export const googleAuth = new Proxy({} as Google, {
	get(target, prop) {
		const auth = createGoogleAuth();
		const value = (auth as any)[prop];
		if (typeof value === 'function') {
			return value.bind(auth);
		}
		return value;
	}
});
