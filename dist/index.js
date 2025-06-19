"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.FirebaseTokenVerifier = void 0;
class FirebaseTokenVerifier {
    constructor(projectId) {
        this.googlePublicKeys = undefined;
        this.project = projectId;
    }
    fetchKeys() {
        return __awaiter(this, void 0, void 0, function* () {
            var _a;
            const response = yield fetch("https://www.googleapis.com/robot/v1/metadata/jwk/securetoken@system.gserviceaccount.com");
            const keys = (yield response.json());
            let expiry = Math.floor(Date.now() / 1000);
            const expiresHeader = response.headers.get("expires");
            if (expiresHeader) {
                expiry = Math.floor(Number(new Date(expiresHeader)) / 1000);
            }
            else {
                const date = new Date((_a = response.headers.get("date")) !== null && _a !== void 0 ? _a : Date.now());
                const headerValue = response.headers.get("cache-control");
                if (headerValue) {
                    const match = headerValue.match(/max-age=(\d+)/);
                    if (match) {
                        const maxAge = parseInt(match[1], 10);
                        expiry = Number(date) / 1000 + maxAge;
                    }
                }
            }
            this.googlePublicKeys = { keys: keys.keys, expiry };
            return this.googlePublicKeys;
        });
    }
    getKey(kid) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.googlePublicKeys ||
                this.googlePublicKeys.expiry < Math.floor(Date.now() / 1000)) {
                yield this.fetchKeys();
            }
            for (const key of this.googlePublicKeys.keys) {
                if (key.kid === kid) {
                    return crypto.subtle.importKey("jwk", key, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
                }
            }
            throw new Error("Couldn't find key associated with that kid");
        });
    }
    verifyToken(token) {
        return __awaiter(this, void 0, void 0, function* () {
            const parts = token.split(".");
            const header = JSON.parse(atob(parts[0]));
            const payload = JSON.parse(atob(parts[1]));
            if (!("kid" in header && typeof header["kid"] === "string")) {
                throw new Error("'kid' is not present in header");
            }
            const isProjectMatched = "aud" in payload &&
                typeof payload["aud"] === "string" &&
                payload["aud"] == this.project;
            if (!isProjectMatched) {
                throw new Error("'aud' is not matched with project id");
            }
            const isNotExpired = "exp" in payload &&
                typeof payload["exp"] === "number" &&
                payload["exp"] * 1000 < Date.now();
            const key = yield this.getKey(header.kid);
            const data = new TextEncoder().encode([parts[0], parts[1]].join("."));
            const signature = Uint8Array.from(Array.from(atob(parts[2].replace(/_/g, "/").replace(/-/g, "+"))).map((c) => c.charCodeAt(0)));
            const algorithm = {
                name: "RSASSA-PKCS1-v1_5",
                hash: "SHA-256",
            };
            const isValid = yield crypto.subtle.verify(algorithm, key, signature, data);
            return {
                header,
                payload,
                signature,
                isValid: isValid && isNotExpired,
            };
        });
    }
}
exports.FirebaseTokenVerifier = FirebaseTokenVerifier;
