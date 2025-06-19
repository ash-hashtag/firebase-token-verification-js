interface GooglePublicKeysResult {
  keys: GooglePublicKey[];
  expiry: number;
}

interface GooglePublicKeys {
  keys: GooglePublicKey[];
}

interface GooglePublicKey {
  alg: string;
  e: string;
  kid: string;
  n: string;
  kty: string;
  use: string;
}

export class FirebaseTokenVerifier {
  project: string;
  googlePublicKeys: GooglePublicKeysResult | undefined = undefined;

  constructor(projectId: string) {
    this.project = projectId;
  }

  async fetchKeys() {
    const response = await fetch(
      "https://www.googleapis.com/robot/v1/metadata/jwk/securetoken@system.gserviceaccount.com",
    );
    const keys: GooglePublicKeys = (await response.json()) as GooglePublicKeys;
    let expiry = Math.floor(Date.now() / 1000);

    const expiresHeader = response.headers.get("expires");
    if (expiresHeader) {
      expiry = Math.floor(Number(new Date(expiresHeader)) / 1000);
    } else {
      const date = new Date(response.headers.get("date") ?? Date.now());
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
  }

  async getKey(kid: string) {
    if (
      !this.googlePublicKeys ||
      this.googlePublicKeys!.expiry < Math.floor(Date.now() / 1000)
    ) {
      await this.fetchKeys();
    }
    for (const key of this.googlePublicKeys!.keys) {
      if (key.kid === kid) {
        return crypto.subtle.importKey(
          "jwk",
          key,
          { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
          false,
          ["verify"],
        );
      }
    }

    throw new Error("Couldn't find key associated with that kid");
  }

  async verifyToken(token: string) {
    const parts = token.split(".");
    const header = JSON.parse(atob(parts[0]));
    const payload = JSON.parse(atob(parts[1]));

    if (!("kid" in header && typeof header["kid"] === "string")) {
      throw new Error("'kid' is not present in header");
    }

    const isProjectMatched =
      "aud" in payload &&
      typeof payload["aud"] === "string" &&
      payload["aud"] == this.project;

    if (!isProjectMatched) {
      throw new Error("'aud' is not matched with project id");
    }
    const isNotExpired =
      "exp" in payload &&
      typeof payload["exp"] === "number" &&
      payload["exp"] * 1000 < Date.now();

    const key = await this.getKey(header.kid);
    const data = new TextEncoder().encode([parts[0], parts[1]].join("."));

    const signature = Uint8Array.from(
      Array.from(atob(parts[2].replace(/_/g, "/").replace(/-/g, "+"))).map(
        (c) => c.charCodeAt(0),
      ),
    );

    const algorithm = {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    };
    const isValid = await crypto.subtle.verify(algorithm, key, signature, data);

    return {
      header,
      payload,
      signature,
      isValid: isValid && isNotExpired,
    };
  }
}
