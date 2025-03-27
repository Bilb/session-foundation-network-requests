import {
  Uint8ArrayLen64,
  concatUInt8Array,
  type LibSodiumType,
  GroupPubkeyType,
  PubkeyPrefix,
  PubkeyType,
  WithGroupPubkey,
  fromUInt8ArrayToBase64,
  fromUtf8ToUInt8Array,
  toHex,
  type WithSessionID,
  type WithLibSodium,
  type Uint8ArrayLen100,
  assertUnreachable,
} from '@session-foundation/basic-types';

import { isEmpty, isString } from 'lodash';
import { Logger } from './fake_logger'; // FIXME TODO
import type {
  WithSignature,
  WithTimestamp,
  WithGetNow,
  WithAdminSecretKey,
  WithMessagesHashes,
  WithShortenOrExtend,
} from './with';

export type SnodeSignatureResult = WithSignature &
  WithTimestamp & {
    pubkey_ed25519: string;
    pubkey: string; // this is the x25519 key of the pubkey we are doing the request to (ourself for our swarm usually)
  };

export type SnodeSigParamsShared = {
  namespace: number | null | 'all'; // 'all' can be used to clear all namespaces (during account deletion)
  method: 'retrieve' | 'store' | 'delete_all';
};

type SnodeSigParamsSubAccount = SnodeSigParamsShared & {
  groupPk: GroupPubkeyType;
  authData: Uint8ArrayLen100; // len 100
};

export type SnodeSigParamsAdminGroup = SnodeSigParamsShared & {
  groupPk: GroupPubkeyType;
  /**
   * privKey, length of 64 bytes
   */
  privKey: Uint8ArrayLen64;
};

export type SnodeSigParamsUs = SnodeSigParamsShared & {
  pubKey: string;
  privKey: Uint8ArrayLen64; // len 64
};

export type SignedHashesParams = WithSignature & {
  pubkey: PubkeyType;
  pubkey_ed25519: PubkeyType;
  messages: Array<string>;
};

export type WithUserSigner = {
  userSigner: UserSigner;
};
export type WithUserSessionProtocolDecryptor = {
  userSessionProtocolDecryptor: UserSessionProtocolDecryptor;
};
export type WithAdminGroupSigner = {
  adminGroupSigner: AdminGroupSigner;
};

export type WithGroupSigner = {
  groupSigner: GroupSigner;
};

type ParamsShared = WithGetNow & {
  groupPk: GroupPubkeyType;
  namespace: number | null | 'all';
  method: 'retrieve' | 'store' | 'delete_all';
};

type SigResultAdmin = WithSignature &
  WithTimestamp & {
    pubkey: GroupPubkeyType; // this is the 03 pubkey of the corresponding group
  };

type SigResultSubAccount = SigResultAdmin & {
  subaccount: string;
  subaccount_sig: string;
};

export class UserSigner {
  private readonly ed25519PubKey: string;
  private readonly ed25519PrivKey: Uint8Array;
  public readonly sessionId: PubkeyType;
  protected readonly sodium: LibSodiumType;

  constructor({
    ed25519PrivKey,
    ed25519PubKey,
    sessionId,
    sodium,
  }: WithSessionID &
    WithLibSodium & {
      ed25519PubKey: string;
      ed25519PrivKey: Uint8ArrayLen64;
    }) {
    this.ed25519PubKey = ed25519PubKey;
    this.sodium = sodium;
    this.sodium.crypto_core_ed25519_scalar_add;
    if (this.ed25519PubKey.length !== 64) {
      console.warn('ed25519PubKey length', ed25519PubKey.length);
      throw new Error('ed25519PubKey not 64 long');
    }
    this.ed25519PrivKey = ed25519PrivKey;
    if (this.ed25519PrivKey.length !== 64) {
      console.warn('ed25519PrivKey length', ed25519PrivKey.length);
      throw new Error('ed25519PrivKey not 64 long');
    }
    this.sessionId = sessionId;
  }

  public getSnodeSignatureParams({
    method,
    namespace = 0,
    getNow,
  }: Pick<SnodeSigParamsUs, 'method' | 'namespace'> &
    WithGetNow): SnodeSignatureResult {
    if (!this.ed25519PrivKey || !this.ed25519PubKey) {
      const err = `getSnodeSignatureParams "${method}": User has no getUserED25519KeyPairBytes()`;
      Logger.warn(err);
      throw new Error(err);
    }

    const sigData = getSnodeSignatureShared({
      pubKey: this.sessionId,
      method,
      namespace,
      privKey: this.ed25519PrivKey,
      getNow,
      sodium: this.sodium,
    });

    return {
      ...sigData,
      pubkey_ed25519: this.ed25519PubKey,
      pubkey: this.sessionId,
    };
  }

  public getSnodeSignatureByHashesParams(
    params: WithMessagesHashes & {
      pubkey: PubkeyType;
    } & Parameters<typeof getVerificationDataForHashes>[0]
  ): SignedHashesParams {
    const verificationData = getVerificationDataForHashes({
      ...params,
    });

    const signature = this.sodium.crypto_sign_detached(
      verificationData,
      this.ed25519PrivKey
    );
    const signatureBase64 = fromUInt8ArrayToBase64(signature);

    return {
      signature: signatureBase64,
      pubkey_ed25519: this.ed25519PubKey as PubkeyType,
      pubkey: params.pubkey,
      messages: params.messagesHashes,
    };
  }

  public getUpdateExpirySignature({
    shortenOrExtend,
    timestamp,
    messagesHashes,
  }: WithMessagesHashes &
    WithShortenOrExtend &
    WithTimestamp): WithSignature & { pubkey: string } {
    // "expire" || ShortenOrExtend || expiry || messages[0] || ... || messages[N]
    const verificationString = `expire${shortenOrExtend}${timestamp}${messagesHashes.join(
      ''
    )}`;
    const message = fromUtf8ToUInt8Array(verificationString);

    const signature = this.sodium.crypto_sign_detached(
      message,
      this.ed25519PrivKey
    );
    const signatureBase64 = fromUInt8ArrayToBase64(signature);

    return {
      signature: signatureBase64,
      pubkey: this.ed25519PubKey,
    };
  }
}

export class UserSessionProtocolDecryptor {
  private readonly ed25519PubKey: Uint8Array;
  private readonly ed25519PrivKey: Uint8Array;
  private readonly x25519Pubkey: Uint8Array;
  private readonly x25519Privkey: Uint8Array;
  private readonly sodium: LibSodiumType;

  constructor({
    ed25519PrivKey,
    ed25519PubKey,
    sodium,
  }: {
    ed25519PubKey: Uint8Array;
    ed25519PrivKey: Uint8ArrayLen64;
    sodium: LibSodiumType;
  }) {
    this.ed25519PubKey = ed25519PubKey;
    if (this.ed25519PubKey.length !== 32) {
      console.warn('ed25519PubKey length', ed25519PubKey.length);
      throw new Error('ed25519PubKey not 64 long');
    }
    this.ed25519PrivKey = ed25519PrivKey;
    if (this.ed25519PrivKey.length !== 64) {
      console.warn('ed25519PrivKey length', ed25519PrivKey.length);
      throw new Error('ed25519PrivKey not 64 long');
    }
    this.x25519Pubkey = sodium.crypto_sign_ed25519_pk_to_curve25519(
      this.ed25519PubKey
    );
    this.x25519Privkey = sodium.crypto_sign_ed25519_sk_to_curve25519(
      this.ed25519PrivKey
    );
    if (!this.x25519Pubkey.length) {
      throw new Error('x25519Pubkey invalid');
    }
    if (!this.x25519Privkey.length) {
      throw new Error('x25519Privkey invalid');
    }
    this.sodium = sodium;
  }

  decrypt(cipherText: Uint8Array) {
    const plaintextWithMetadata = this.sodium.crypto_box_seal_open(
      new Uint8Array(cipherText),
      this.x25519Pubkey,
      this.x25519Privkey
    );
    const signatureSize = this.sodium.crypto_sign_BYTES;
    const ed25519PublicKeySize = this.sodium.crypto_sign_PUBLICKEYBYTES;

    if (
      plaintextWithMetadata.byteLength <=
      signatureSize + ed25519PublicKeySize
    ) {
      throw new Error('UserSessionProtocolDecryptor Decryption failed.');
    }

    // 2. ) Get the message parts
    const signatureStart = plaintextWithMetadata.byteLength - signatureSize;
    const signature = plaintextWithMetadata.subarray(signatureStart);
    const pubkeyStart =
      plaintextWithMetadata.byteLength - (signatureSize + ed25519PublicKeySize);
    const pubkeyEnd = plaintextWithMetadata.byteLength - signatureSize;
    const senderED25519PublicKey = plaintextWithMetadata.subarray(
      pubkeyStart,
      pubkeyEnd
    );
    const plainTextEnd =
      plaintextWithMetadata.byteLength - (signatureSize + ed25519PublicKeySize);
    const plaintext = plaintextWithMetadata.subarray(0, plainTextEnd);

    // 3. ) Verify the signature
    const isValid = this.sodium.crypto_sign_verify_detached(
      signature,
      concatUInt8Array(plaintext, senderED25519PublicKey, this.x25519Pubkey),
      senderED25519PublicKey
    );

    if (!isValid) {
      throw new Error(
        'UserSessionProtocolDecryptor Invalid message signature.'
      );
    }
    // 4. ) Get the sender's X25519 public key
    const senderX25519PublicKey =
      this.sodium.crypto_sign_ed25519_pk_to_curve25519(senderED25519PublicKey);
    if (!senderX25519PublicKey) {
      throw new Error('UserSessionProtocolDecryptor Decryption failed.');
    }

    const sender = `${PubkeyPrefix.standard}${toHex(
      senderX25519PublicKey
    )}` as PubkeyType;

    return { decryptedContent: plaintext, sender };
  }
}

export function getVerificationDataForStoreRetrieve(
  params: SnodeSigParamsShared & WithGetNow
) {
  const signatureTimestamp = params.getNow();
  const verificationString = `${params.method}${
    params.namespace === 0 ? '' : params.namespace
  }${signatureTimestamp}`;
  const verificationData = fromUtf8ToUInt8Array(verificationString);
  return {
    toSign: new Uint8Array(verificationData),
    signatureTimestamp,
  };
}

function getVerificationDataForHashes(
  params: WithMessagesHashes &
    (
      | {
          method: 'delete'; // ("delete" || messages[0] || ... || messages[N])
        }
      | ({
          method: 'get_expiries'; // ("get_expiries" || timestamp || messages[0] || ... || messages[N])
        } & WithTimestamp)
      | ({
          method: 'expire'; //    "expire" || ShortenOrExtend || expiry || messages[0] || ... || messages[N]
        } & WithShortenOrExtend &
          WithTimestamp)
    )
) {
  const { method } = params;
  switch (method) {
    case 'delete':
      return fromUtf8ToUInt8Array(
        `${params.method}${params.messagesHashes.join('')}`
      );
    case 'get_expiries':
      return fromUtf8ToUInt8Array(
        `${params.method}${params.timestamp}${params.messagesHashes.join('')}`
      );
    case 'expire':
      return fromUtf8ToUInt8Array(
        `${method}${params.shortenOrExtend}${
          params.timestamp
        }${params.messagesHashes.join('')}`
      );
    default:
      assertUnreachable(method, 'unhandled case');
  }
}

function getSnodeSignatureShared(
  params: (SnodeSigParamsAdminGroup | SnodeSigParamsUs) &
    WithGetNow &
    WithLibSodium
) {
  const { signatureTimestamp, toSign } =
    getVerificationDataForStoreRetrieve(params);

  const signature = params.sodium.crypto_sign_detached(toSign, params.privKey);
  const signatureBase64 = fromUInt8ArrayToBase64(signature);

  return {
    timestamp: signatureTimestamp,
    signature: signatureBase64,
  };
}

/**
 * Groups signature logic
 */
export class AdminGroupSigner {
  public readonly groupPk: GroupPubkeyType;
  protected readonly sodium: LibSodiumType;
  private readonly adminSecretKey: Uint8Array;
  private readonly getNow: () => number;

  constructor({
    adminSecretKey,
    groupPk,
    sodium,
    getNow,
  }: WithAdminSecretKey & WithGroupPubkey & WithLibSodium & WithGetNow) {
    if (!adminSecretKey || isEmpty(adminSecretKey)) {
      throw new Error(`AdminGroupSigner: we need adminSecretKey`);
    }
    this.adminSecretKey = adminSecretKey;
    this.groupPk = groupPk;
    this.sodium = sodium;
    this.getNow = getNow;
  }

  public async getRetrieveStoreSignature(
    params: Pick<ParamsShared, 'method' | 'namespace'>
  ): Promise<SigResultAdmin> {
    const sigData = getSnodeSignatureShared({
      method: params.method,
      namespace: params.namespace,
      getNow: this.getNow,
      groupPk: this.groupPk,
      privKey: this.adminSecretKey,
      sodium: this.sodium,
    });
    return { ...sigData, pubkey: this.groupPk };
  }

  public signContent(verificationString: string | Uint8Array) {
    const message = isString(verificationString)
      ? fromUtf8ToUInt8Array(verificationString)
      : verificationString;
    return fromUInt8ArrayToBase64(
      this.sodium.crypto_sign_detached(message, this.adminSecretKey)
    );
  }

  public signDeleteByHashes({
    messagesHashes,
    method,
  }: WithMessagesHashes & {
    method: 'delete';
  }) {
    const verificationString = `${method}${messagesHashes.join('')}`;
    const message = fromUtf8ToUInt8Array(verificationString);

    const signatureBase64 = this.signContent(message);

    return {
      signature: signatureBase64,
      pubkey: this.groupPk,
      messages: messagesHashes,
      // timestamp: signatureTimestamp, // this one shouldn't need a delete by hashes right?
    };
  }

  public getUpdateExpirySignature({
    shortenOrExtend,
    timestamp,
    messagesHashes,
  }: WithMessagesHashes &
    WithShortenOrExtend &
    WithTimestamp): WithSignature & { pubkey: string } {
    // "expire" || ShortenOrExtend || expiry || messages[0] || ... || messages[N]
    const verificationString = `expire${shortenOrExtend}${timestamp}${messagesHashes.join(
      ''
    )}`;
    const message = fromUtf8ToUInt8Array(verificationString);

    const signatureBase64 = this.signContent(message);

    return {
      signature: signatureBase64,
      pubkey: this.groupPk,
    };
  }

  public getUpdateExpiryGroupSignature({
    shortenOrExtend,
    expiryMs,
    messagesHashes,
  }: WithMessagesHashes &
    WithShortenOrExtend & {
      expiryMs: number;
    }) {
    // "expire" || ShortenOrExtend || expiry || messages[0] || ... || messages[N]
    const verificationString = `expire${shortenOrExtend}${expiryMs}${messagesHashes.join(
      ''
    )}`;

    // expiry and the other fields come from what the expire endpoint expects
    const shared = { expiry: expiryMs, pubkey: this.groupPk };

    return {
      signature: this.signContent(verificationString),
      ...shared,
    };
  }
}

export interface UserInGroupSignerInterface {
  readonly groupPk: GroupPubkeyType;

  getRetrieveStoreSignature(params: {
    namespace: number;
    method: 'retrieve' | 'store';
  }): Promise<SigResultSubAccount>;

  getUpdateExpiryGroupSignature({
    shortenOrExtend,
    expiryMs,
    messagesHashes,
  }: WithMessagesHashes &
    WithShortenOrExtend & {
      expiryMs: number;
    }): Promise<SigResultSubAccount>;
}

export type GroupSigner = AdminGroupSigner | UserInGroupSignerInterface;
