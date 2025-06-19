interface GooglePublicKeysResult {
    keys: GooglePublicKey[];
    expiry: number;
}
interface GooglePublicKey {
    alg: string;
    e: string;
    kid: string;
    n: string;
    kty: string;
    use: string;
}
export declare class FirebaseTokenVerifier {
    project: string;
    googlePublicKeys: GooglePublicKeysResult | undefined;
    constructor(projectId: string);
    fetchKeys(): Promise<GooglePublicKeysResult>;
    getKey(kid: string): Promise<CryptoKey>;
    verifyToken(token: string): Promise<{
        header: any;
        payload: any;
        signature: Uint8Array<ArrayBuffer>;
        isValid: boolean;
    }>;
}
export {};
