export default class AuthorizationEnforcer {
    /**
     * @param {string} key
     */
    constructor(key) {
        this.key = key;
    }

    /**
     * @param {object} ctx
     */
    verifyRequest(ctx) {
        const authHeader = ctx.request.headers.authorization;
        if (!authHeader) {
            throw new Error('No Authorization header provided.');
        }

        const buffer = new Buffer(authHeader.substr('Basic '.length), 'base64');
        
        //  We currently don't use a username:password combination, so this suffices.
        let receivedAPIKey = buffer.toString('ascii');
        receivedAPIKey = receivedAPIKey.substr(0, receivedAPIKey.length - 1);

        if (receivedAPIKey !== this.key) {
            throw new Error('Invalid auth.');
        }
    }
}