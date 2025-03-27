import {
  assertUnreachable,
  concatUInt8Array,
  fromHex,
  fromUInt8ArrayToBase64,
  fromUtf8ToUInt8Array,
  is03Pubkey,
  isHex,
  shortenPk,
  type AwaitedReturn,
  type GroupPubkeyType,
  type HexString,
  type PubkeyType,
  type Uint8ArrayLen100,
  type Uint8ArrayLen64,
  type WithGroupPubkey,
  type WithSessionID,
} from '@session-foundation/basic-types';
import type {
  ShortenOrExtend,
  WithCreatedAtNetworkTimestamp,
  WithDestination,
  WithGetNow,
  WithMaxSize,
  WithMessagesHashes,
  WithMethod,
  WithShortenOrExtend,
  WithSignature,
  WithTimestamp,
} from './with';
import {
  SnodeNamespace,
  SnodeNamespaces,
  type SnodeNamespacesGroup,
  type SnodeNamespacesGroupConfig,
  type SnodeNamespacesUser,
  type SnodeNamespacesUserConfig,
} from './namespaces';
import { isEmpty, isString } from 'lodash';
import {
  AdminGroupSigner,
  GroupSigner,
  UserSigner,
  WithAdminGroupSigner,
  WithGroupSigner,
  WithUserSigner,
} from './signer';

/**
 * This is the base sub request class that every other type of request has to extend.
 */
abstract class SnodeAPISubRequest<T extends string> {
  public method: T;

  public abstract loggingId(): string;
  public abstract getDestination(): PubkeyType | GroupPubkeyType | '<none>';
  public abstract build(): Promise<Record<string, unknown>>;

  public async toBody() {
    return JSON.stringify(await this.build());
  }

  constructor({ method }: WithMethod<T>) {
    this.method = method;
  }

  /**
   * When batch sending an array of requests, we will sort them by this number (the smallest will be put in front and the largest at the end).
   * This is needed for sending and polling for 03-group keys for instance.
   */

  public requestOrder() {
    return 0;
  }
}

abstract class SnodeRequestWithDestination<
  M extends string,
  T extends PubkeyType | GroupPubkeyType
> extends SnodeAPISubRequest<M> {
  public readonly destination: T;

  constructor(args: WithMethod<M> & WithDestination<T>) {
    super(args);
    this.destination = args.destination;
    if (!args.destination) {
      throw new Error(
        `[SnodeRequestWithDestination] No destination for method: ${args.method}`
      );
    }
  }

  public getDestination() {
    return this.destination;
  }
}

abstract class RetrieveSubRequest<
  T extends PubkeyType | GroupPubkeyType
> extends SnodeRequestWithDestination<'retrieve', T> {
  protected readonly last_hash: string;
  protected readonly max_size: number | undefined;

  constructor({
    last_hash,
    max_size,
    destination,
  }: WithMaxSize & WithDestination<T> & { last_hash: string }) {
    super({ method: 'retrieve', destination });
    this.last_hash = last_hash;
    this.max_size = max_size;
  }
}

abstract class OxendSubRequest extends SnodeAPISubRequest<'oxend_request'> {
  constructor() {
    super({ method: 'oxend_request' });
  }
}

abstract class DeleteAllSubRequest<
  T extends PubkeyType | GroupPubkeyType
> extends SnodeRequestWithDestination<'delete_all', T> {
  constructor(args: WithDestination<T>) {
    super({ method: 'delete_all', ...args });
  }
}

abstract class DeleteSubRequest<
  T extends PubkeyType | GroupPubkeyType
> extends SnodeRequestWithDestination<'delete', T> {
  constructor(args: WithDestination<T>) {
    super({ method: 'delete', ...args });
  }
}

abstract class StoreSubRequest<
  T extends PubkeyType | GroupPubkeyType
> extends SnodeRequestWithDestination<'store', T> {
  protected readonly getNow: () => number;

  constructor(args: WithGetNow & WithDestination<T>) {
    super({ method: 'store', ...args });
    this.getNow = args.getNow;
  }
}

/**
 * If you are thinking of adding the `limit` field here: don't.
 * We fetch the full list because we will remove from every cached swarms the snodes not found in that fresh list.
 * If a `limit` was set, we would remove a lot of valid snodes from those cached swarms.
 */
type FetchSnodeListParams = {
  active_only: true;
  fields: {
    public_ip: true;
    storage_port: true;
    pubkey_x25519: true;
    pubkey_ed25519: true;
    storage_server_version: true;
  };
};

export type GetServicesNodesFromSeedRequest = {
  method: 'get_n_service_nodes';
  jsonrpc: '2.0';
  /**
   * If you are thinking of adding the `limit` field here: don't.
   * We fetch the full list because we will remove from every cached swarms the snodes not found in that fresh list.
   * If the limit was set, we would remove a lot of valid snodes from the swarms we've already fetched.
   */
  params: FetchSnodeListParams;
};

export type GroupDetailsNeededForSignature = {
  /**
   * The group "session id" (33 bytes), starting with 03.
   */
  groupPk: GroupPubkeyType;
  /**
   * The group admin secret key if we have it, length 64.
   */
  secretKey: Uint8ArrayLen64 | null;
  /**
   * The group auth data we were given if we have it, length 100.
   */
  authData: Uint8ArrayLen100 | null;
};

export class RetrieveUserSubRequest extends RetrieveSubRequest<PubkeyType> {
  private readonly namespace: SnodeNamespacesUser | SnodeNamespacesUserConfig;
  private readonly userSigner: UserSigner;
  private readonly getNow: () => number;

  constructor({
    last_hash,
    max_size,
    namespace,
    sessionId,
    userSigner,
    getNow,
  }: WithMaxSize &
    WithSessionID &
    WithGetNow &
    WithUserSigner & {
      last_hash: string;
      namespace: SnodeNamespacesUser | SnodeNamespacesUserConfig;
    }) {
    super({ last_hash, max_size, destination: sessionId });
    this.namespace = namespace;
    this.userSigner = userSigner;
    this.getNow = getNow;
  }

  public async build() {
    const { pubkey, pubkey_ed25519, signature, timestamp } =
      this.userSigner.getSnodeSignatureParams({
        method: this.method,
        namespace: this.namespace,
        getNow: this.getNow,
      });

    return {
      method: this.method,
      params: {
        namespace: this.namespace,
        pubkey,
        pubkey_ed25519,
        signature,
        timestamp, // we give a timestamp to force verification of the signature provided
        last_hash: this.last_hash,
        max_size: this.max_size,
      },
    };
  }

  public loggingId(): string {
    return `${this.method}-${SnodeNamespace.toRole(this.namespace)}`;
  }
}

/**
 * Build and sign a request with either the admin key if we have it, or with our sub account details
 */
export class RetrieveGroupSubRequest extends RetrieveSubRequest<GroupPubkeyType> {
  private readonly namespace: SnodeNamespacesGroup;
  private readonly groupSigner: GroupSigner;
  private readonly getNow: () => number;

  constructor({
    last_hash,
    max_size,
    namespace,
    groupSigner,
    getNow,
  }: WithMaxSize &
    WithGroupSigner &
    WithGetNow & {
      last_hash: string;
      namespace: SnodeNamespacesGroup;
    }) {
    super({
      last_hash,
      max_size,
      destination: groupSigner.groupPk,
    });
    this.namespace = namespace;
    this.groupSigner = groupSigner;
    this.getNow = getNow;
  }

  public async build() {
    /**
     * This will return the signature details we can use with the admin secretKey if we have it,
     * or with the sub account details if we don't.
     * If there is no valid groupDetails, this throws
     */
    const sigResult = await this.groupSigner.getRetrieveStoreSignature({
      method: this.method,
      namespace: this.namespace,
    });

    return {
      method: this.method,
      params: {
        namespace: this.namespace,
        ...sigResult,
        last_hash: this.last_hash,
        max_size: this.max_size,
      },
    };
  }

  public loggingId(): string {
    return `${this.method}-${SnodeNamespace.toRole(this.namespace)}`;
  }

  public override requestOrder() {
    if (this.namespace === SnodeNamespaces.ClosedGroupKeys) {
      // we want to retrieve the groups keys last
      return 10;
    }

    return super.requestOrder();
  }
}

export class OnsResolveSubRequest extends OxendSubRequest {
  private readonly base64EncodedNameHash: string;

  constructor(base64EncodedNameHash: string) {
    super();
    this.base64EncodedNameHash = base64EncodedNameHash;
  }

  public async build() {
    return {
      method: this.method,
      params: {
        endpoint: 'ons_resolve',
        params: {
          type: 0,
          name_hash: this.base64EncodedNameHash,
        },
      },
    };
  }

  public loggingId(): string {
    return `${this.method}`;
  }

  public getDestination() {
    return '<none>' as const;
  }
}

export class GetServiceNodesSubRequest extends OxendSubRequest {
  public async build() {
    return {
      method: this.method,
      params: {
        /**
         * If you are thinking of adding the `limit` field here: don't.
         * We fetch the full list because we will remove from every cached swarms the snodes not found in that fresh list.
         * If the limit was set, we would remove a lot of valid snodes from the swarms we've already fetched.
         */
        endpoint: 'get_service_nodes' as const,
        params: {
          active_only: true,
          fields: {
            public_ip: true,
            storage_port: true,
            pubkey_x25519: true,
            pubkey_ed25519: true,
          },
        },
      },
    };
  }

  public loggingId(): string {
    return `${this.method}`;
  }

  public getDestination() {
    return '<none>' as const;
  }
}

export class SwarmForSubRequest extends SnodeRequestWithDestination<
  'get_swarm',
  PubkeyType | GroupPubkeyType
> {
  constructor(pubkey: PubkeyType | GroupPubkeyType) {
    super({ method: 'get_swarm', destination: pubkey });
  }

  public async build() {
    return {
      method: this.method,
      params: {
        pubkey: this.destination,
        params: {
          active_only: true,
          fields: {
            public_ip: true,
            storage_port: true,
            pubkey_x25519: true,
            pubkey_ed25519: true,
          },
        },
      },
    } as const;
  }

  public loggingId(): string {
    return `${this.method}`;
  }
}

export class NetworkTimeSubRequest extends SnodeAPISubRequest<'info'> {
  constructor() {
    super({ method: 'info' });
  }

  public async build() {
    return {
      method: this.method,
      params: {},
    } as const;
  }

  public loggingId(): string {
    return `${this.method}`;
  }

  public getDestination() {
    return '<none>' as const;
  }
}

class RevokeOrNotSubRequest<
  T extends 'revoke_subaccount' | 'unrevoke_subaccount'
> extends SnodeRequestWithDestination<T, GroupPubkeyType> {
  private readonly timestamp: number;
  private readonly tokensHex: Array<HexString>;
  private readonly adminGroupSigner: AdminGroupSigner;

  constructor({
    groupPk,
    timestamp,
    tokensHex,
    method,
    adminGroupSigner,
  }: WithGroupPubkey &
    WithTimestamp &
    WithAdminGroupSigner & { tokensHex: Array<string>; method: T }) {
    super({ method, destination: groupPk });

    this.timestamp = timestamp;
    this.adminGroupSigner = adminGroupSigner;
    if (tokensHex.some((m) => !isHex(m))) {
      throw new Error('some tokens are not hex');
    }
    this.tokensHex = tokensHex as Array<HexString>;

    if (this.tokensHex.length === 0) {
      throw new Error(
        'AbstractRevokeSubRequest needs at least one token to do a change'
      );
    }
  }

  /**
   * For Revoke/unrevoke, this needs an admin signature
   */
  public async build() {
    const tokensBytes = fromHex(this.tokensHex.join('') as HexString);

    const prefix = fromUtf8ToUInt8Array(`${this.method}${this.timestamp}`);

    const signature = this.adminGroupSigner.signContent(
      concatUInt8Array(prefix, tokensBytes)
    );

    return {
      method: this.method,
      params: {
        pubkey: this.destination,
        signature,
        unrevoke: this.tokensHex,
        timestamp: this.timestamp,
      },
    };
  }

  public loggingId(): string {
    return `${this.method}-${shortenPk(this.destination)}`;
  }
}

export class SubaccountRevokeSubRequest extends RevokeOrNotSubRequest<'revoke_subaccount'> {
  constructor(
    args: Omit<ConstructorParameters<typeof RevokeOrNotSubRequest>[0], 'method'>
  ) {
    super({ method: 'revoke_subaccount', ...args });
  }
}

export class SubaccountUnrevokeSubRequest extends RevokeOrNotSubRequest<'unrevoke_subaccount'> {
  constructor(
    args: Omit<ConstructorParameters<typeof RevokeOrNotSubRequest>[0], 'method'>
  ) {
    super({ method: 'unrevoke_subaccount', ...args });
  }
}

/**
 * The getExpiries request can currently only be used for our own pubkey as we use it to fetch
 * the expiries updated by another of our devices.
 */
export class GetExpiriesFromNodeSubRequest extends SnodeRequestWithDestination<
  'get_expiries',
  PubkeyType
> {
  private readonly messageHashes: Array<string>;
  private readonly getNow: () => number;
  private readonly userSigner: UserSigner;

  constructor(
    args: WithMessagesHashes &
      WithGetNow &
      WithDestination<PubkeyType> &
      WithUserSigner
  ) {
    super({ method: 'get_expiries', destination: args.destination });
    this.getNow = args.getNow;

    this.messageHashes = args.messagesHashes;
    this.userSigner = args.userSigner;
    if (this.messageHashes.length === 0) {
      throw new Error(
        'GetExpiriesFromNodeSubRequest given empty list of messageHashes'
      );
    }
  }
  /**
   * For Revoke/unrevoke, this needs an admin signature
   */
  public async build() {
    const timestamp = this.getNow();

    const signResult = this.userSigner.getSnodeSignatureByHashesParams({
      timestamp,
      messagesHashes: this.messageHashes,
      pubkey: this.userSigner.sessionId,
      method: 'get_expiries',
    });

    if (!signResult) {
      throw new Error(
        `[GetExpiriesFromNodeSubRequest] SnodeSignature.generateUpdateExpirySignature returned an empty result ${this.messageHashes}`
      );
    }

    return {
      method: this.method,
      params: {
        pubkey: this.destination,
        pubkey_ed25519: signResult.pubkey_ed25519.toUpperCase(),
        signature: signResult.signature,
        messages: this.messageHashes,
        timestamp,
      },
    };
  }

  public loggingId(): string {
    return `${this.method}-us`;
  }
}

export class DeleteAllFromUserNodeSubRequest extends DeleteAllSubRequest<PubkeyType> {
  private readonly namespace = 'all'; // we can only delete_all for all namespaces currently, but the backend allows more
  private readonly userSigner: UserSigner;
  private readonly getNow: () => number;

  constructor(args: WithUserSigner & WithDestination<PubkeyType> & WithGetNow) {
    super(args);
    this.userSigner = args.userSigner;
    this.getNow = args.getNow;
  }

  public async build() {
    const signResult = this.userSigner.getSnodeSignatureParams({
      getNow: this.getNow,
      method: this.method,
      namespace: this.namespace,
    });

    if (!signResult) {
      throw new Error(
        `[DeleteAllFromUserNodeSubRequest] SnodeSignature.getSnodeSignatureParamsUs returned an empty result`
      );
    }

    return {
      method: this.method,
      params: {
        pubkey: signResult.pubkey,
        pubkey_ed25519: signResult.pubkey_ed25519.toUpperCase(),
        signature: signResult.signature,
        timestamp: signResult.timestamp,
        namespace: this.namespace,
      },
    };
  }

  public loggingId(): string {
    return `${this.method}-${this.namespace}`;
  }
}

/**
 * Delete all the messages and not the config messages for that group 03.
 */
export class DeleteAllFromGroupMsgNodeSubRequest extends DeleteAllSubRequest<GroupPubkeyType> {
  private readonly namespace = SnodeNamespaces.ClosedGroupMessages;
  private readonly adminGroupSigner: AdminGroupSigner;

  constructor(args: WithAdminGroupSigner) {
    super({
      destination: args.adminGroupSigner.groupPk,
    });
    this.adminGroupSigner = args.adminGroupSigner;
  }

  public async build() {
    const signDetails = await this.adminGroupSigner.getRetrieveStoreSignature({
      method: this.method,
      namespace: this.namespace,
    });

    return {
      method: this.method,
      params: {
        ...signDetails,
        namespace: this.namespace,
        pubkey: this.adminGroupSigner.groupPk, // not sure this is correct
      },
    };
  }

  public loggingId(): string {
    return `${this.method}-${shortenPk(this.destination)}-${this.namespace}`;
  }
}

/**
 * Delete all the normal and config messages from a group swarm.
 * Note: only used for debugging purposes
 */
export class DeleteAllFromGroupNodeSubRequest extends DeleteAllSubRequest<GroupPubkeyType> {
  private readonly namespace = 'all';
  private readonly adminGroupSigner: AdminGroupSigner;

  constructor(args: WithAdminGroupSigner) {
    super({ destination: args.adminGroupSigner.groupPk });

    this.adminGroupSigner = args.adminGroupSigner;
  }

  public async build() {
    const signDetails = await this.adminGroupSigner.getRetrieveStoreSignature({
      method: this.method,
      namespace: this.namespace,
    });

    return {
      method: this.method,
      params: {
        ...signDetails,
        namespace: this.namespace,
      },
    };
  }

  public loggingId(): string {
    return `${this.method}-${shortenPk(this.destination)}-${this.namespace}`;
  }
}

export class DeleteHashesFromUserNodeSubRequest extends DeleteSubRequest<PubkeyType> {
  private readonly messageHashes: Array<string>;
  private readonly userSigner: UserSigner;

  constructor(
    args: WithMessagesHashes & WithDestination<PubkeyType> & WithUserSigner
  ) {
    super(args);
    this.messageHashes = args.messagesHashes;
    this.userSigner = args.userSigner;

    if (this.messageHashes.length === 0) {
      throw new Error(
        'DeleteHashesFromUserNodeSubRequest given empty list of messageHashes'
      );
    }
  }

  public async build() {
    const signResult = this.userSigner.getSnodeSignatureByHashesParams({
      method: this.method,
      messagesHashes: this.messageHashes,
      pubkey: this.destination,
    });

    return {
      method: this.method,
      params: {
        pubkey: signResult.pubkey,
        pubkey_ed25519: signResult.pubkey_ed25519,
        signature: signResult.signature,
        messages: signResult.messages,
        // timestamp is not needed for this one as the hashes can be deleted only once
      },
    };
  }

  public loggingId(): string {
    return `${this.method}-us`;
  }
}

export class DeleteHashesFromGroupNodeSubRequest extends DeleteSubRequest<GroupPubkeyType> {
  private readonly adminGroupSigner: AdminGroupSigner;
  private readonly messageHashes: Array<string>;

  constructor(args: WithMessagesHashes & WithAdminGroupSigner) {
    super({ destination: args.adminGroupSigner.groupPk });
    this.messageHashes = args.messagesHashes;
    this.adminGroupSigner = args.adminGroupSigner;

    if (this.messageHashes.length === 0) {
      throw new Error(
        'DeleteHashesFromGroupNodeSubRequest given empty list of messageHashes'
      );
    }
  }

  /**
   * This request can only be made by an admin and will be denied otherwise, so we make the secretKey mandatory in the constructor.
   */
  public async build() {
    const signResult = await this.adminGroupSigner.signDeleteByHashes({
      method: this.method,
      messagesHashes: this.messageHashes,
    });

    return {
      method: this.method,
      params: {
        ...signResult,
        // pubkey_ed25519 is forbidden when doing the request for a group
        // timestamp is not needed for this one as the hashes can be deleted only once
      },
    };
  }

  public loggingId(): string {
    return `${this.method}-${shortenPk(this.destination)}`;
  }
}

export class UpdateExpiryOnNodeUserSubRequest extends SnodeRequestWithDestination<
  'expire',
  PubkeyType
> {
  private readonly messageHashes: Array<string>;
  private readonly expiryMs: number;
  private readonly shortenOrExtend: ShortenOrExtend;
  private readonly userSigner: UserSigner;

  constructor(
    args: WithMessagesHashes &
      WithShortenOrExtend & { expiryMs: number } & WithDestination<PubkeyType> &
      WithUserSigner
  ) {
    super({ destination: args.destination, method: 'expire' });
    this.messageHashes = args.messagesHashes;
    this.expiryMs = args.expiryMs;
    this.shortenOrExtend = args.shortenOrExtend;
    this.userSigner = args.userSigner;

    if (this.messageHashes.length === 0) {
      throw new Error(
        'UpdateExpiryOnNodeUserSubRequest given empty list of messageHashes'
      );
    }
  }

  public async build() {
    const signResult = this.userSigner.getUpdateExpirySignature({
      shortenOrExtend: this.shortenOrExtend,
      messagesHashes: this.messageHashes,
      timestamp: this.expiryMs,
    });

    if (!signResult) {
      throw new Error(
        `[UpdateExpiryOnNodeUserSubRequest] SnodeSignature.getSnodeSignatureParamsUs returned an empty result`
      );
    }

    const shortenOrExtend =
      this.shortenOrExtend === 'extend'
        ? { extend: true }
        : this.shortenOrExtend === 'shorten'
        ? { shorten: true }
        : {};

    return {
      method: this.method,
      params: {
        pubkey: this.destination,
        pubkey_ed25519: signResult.pubkey,
        signature: signResult.signature,
        messages: this.messageHashes,
        expiry: this.expiryMs,
        ...shortenOrExtend,
      },
    };
  }

  public loggingId(): string {
    return `${this.method}-us`;
  }
}

export class UpdateExpiryOnNodeGroupSubRequest extends SnodeRequestWithDestination<
  'expire',
  GroupPubkeyType
> {
  private readonly messageHashes: Array<string>;
  private readonly expiryMs: number;
  private readonly shortenOrExtend: ShortenOrExtend;
  private readonly groupSigner: GroupSigner;

  constructor(
    args: WithMessagesHashes &
      WithShortenOrExtend &
      WithAdminGroupSigner & {
        expiryMs: number;
      }
  ) {
    super({ destination: args.adminGroupSigner.groupPk, method: 'expire' });
    this.messageHashes = args.messagesHashes;
    this.expiryMs = args.expiryMs;
    this.shortenOrExtend = args.shortenOrExtend;
    this.groupSigner = args.adminGroupSigner;

    if (this.messageHashes.length === 0) {
      throw new Error(
        'UpdateExpiryOnNodeGroupSubRequest given empty list of messageHashes'
      );
    }
  }

  public async build() {
    const signResult = await this.groupSigner.getUpdateExpiryGroupSignature({
      shortenOrExtend: this.shortenOrExtend,
      messagesHashes: this.messageHashes,
      expiryMs: this.expiryMs,
    });

    if (!signResult) {
      throw new Error(
        `[UpdateExpiryOnNodeUserSubRequest] SnodeSignature.getSnodeSignatureParamsUs returned an empty result`
      );
    }

    const shortenOrExtend =
      this.shortenOrExtend === 'extend'
        ? { extends: true }
        : this.shortenOrExtend === 'shorten'
        ? { shorten: true }
        : {};

    return {
      method: this.method,
      params: {
        messages: this.messageHashes,
        ...shortenOrExtend,
        ...signResult,

        // pubkey_ed25519 is forbidden for the group one
      },
    };
  }

  public loggingId(): string {
    return `${this.method}-${shortenPk(this.destination)}`;
  }
}

export class StoreGroupMessageSubRequest extends StoreSubRequest<GroupPubkeyType> {
  private readonly namespace = SnodeNamespaces.ClosedGroupMessages;
  private readonly ttlMs: number;
  private readonly encryptedData: Uint8Array;
  private readonly dbMessageIdentifier: string | null;
  private readonly secretKey: Uint8Array | null;
  private readonly authData: Uint8Array | null;
  private readonly createdAtNetworkTimestamp: number;
  private readonly groupSigner: GroupSigner;

  constructor(
    args: WithGroupPubkey &
      WithGetNow &
      WithCreatedAtNetworkTimestamp &
      WithGroupSigner & {
        ttlMs: number;
        encryptedData: Uint8Array;
        dbMessageIdentifier: string | null;
        authData: Uint8Array | null;
        secretKey: Uint8Array | null;
      }
  ) {
    super({ ...args, destination: args.groupPk });
    this.ttlMs = args.ttlMs;
    this.encryptedData = args.encryptedData;
    this.dbMessageIdentifier = args.dbMessageIdentifier;
    this.authData = args.authData;
    this.secretKey = args.secretKey;
    this.createdAtNetworkTimestamp = args.createdAtNetworkTimestamp;
    this.groupSigner = args.groupSigner;

    if (isEmpty(this.encryptedData)) {
      throw new Error('this.encryptedData cannot be empty');
    }
    if (!is03Pubkey(this.destination)) {
      throw new Error(
        'StoreGroupMessageSubRequest: group config namespace required a 03 pubkey'
      );
    }
    if (isEmpty(this.secretKey) && isEmpty(this.authData)) {
      throw new Error(
        'StoreGroupMessageSubRequest needs either authData or secretKey to be set'
      );
    }
    if (
      SnodeNamespace.isGroupConfigNamespace(this.namespace) &&
      isEmpty(this.secretKey)
    ) {
      throw new Error(
        `StoreGroupMessageSubRequest: group config namespace [${this.namespace}] requires an adminSecretKey`
      );
    }
  }

  public async build(): Promise<{
    method: 'store';
    params: StoreOnNodeNormalParams;
  }> {
    const encryptedDataBase64 = fromUInt8ArrayToBase64(this.encryptedData);

    // this will either sign with our admin key or with the sub account key if the admin one isn't there
    const signDetails = await this.groupSigner.getRetrieveStoreSignature({
      method: this.method,
      namespace: this.namespace,
    });

    return {
      method: this.method,
      params: {
        ...signDetails,
        namespace: this.namespace,
        ttl: this.ttlMs,
        data: encryptedDataBase64,
        pubkey: this.groupSigner.groupPk,
      },
    };
  }

  public loggingId(): string {
    return `${this.method}-${shortenPk(
      this.destination
    )}-${SnodeNamespace.toRole(this.namespace)}`;
  }
}

abstract class StoreGroupConfigSubRequest<
  T extends
    | SnodeNamespacesGroupConfig
    | SnodeNamespaces.ClosedGroupRevokedRetrievableMessages
> extends StoreSubRequest<GroupPubkeyType> {
  private readonly namespace: T;
  private readonly ttlMs: number;
  private readonly encryptedData: Uint8Array;
  private readonly adminGroupSigner: AdminGroupSigner;

  constructor(
    args: WithGroupPubkey &
      WithGetNow &
      WithAdminGroupSigner & {
        namespace: T;
        encryptedData: Uint8Array;
        ttlMs: number;
      }
  ) {
    super({ ...args, destination: args.groupPk });
    this.namespace = args.namespace;
    this.ttlMs = args.ttlMs;
    this.encryptedData = args.encryptedData;
    this.adminGroupSigner = args.adminGroupSigner;

    if (isEmpty(this.encryptedData)) {
      throw new Error('this.encryptedData cannot be empty');
    }
    if (!is03Pubkey(this.destination)) {
      throw new Error(
        'StoreGroupConfigSubRequest: group config namespace required a 03 pubkey'
      );
    }
  }

  public async build(): Promise<{
    method: 'store';
    params: StoreOnNodeNormalParams;
  }> {
    const encryptedDataBase64 = fromUInt8ArrayToBase64(this.encryptedData);

    const signDetails = await this.adminGroupSigner.getRetrieveStoreSignature({
      method: this.method,
      namespace: this.namespace,
    });

    return {
      method: this.method,
      params: {
        namespace: this.namespace,
        ttl: this.ttlMs,
        data: encryptedDataBase64,
        ...signDetails,
        pubkey: this.adminGroupSigner.groupPk,
      },
    };
  }

  public loggingId(): string {
    return `${this.method}-${shortenPk(
      this.destination
    )}-${SnodeNamespace.toRole(this.namespace)}`;
  }

  public requestOrder(): number {
    if (this.namespace === SnodeNamespaces.ClosedGroupKeys) {
      // -10 means that we need this request to be sent before something with an order of 0 for instance
      return -10;
    }
    return super.requestOrder();
  }
}

export class StoreGroupInfoSubRequest extends StoreGroupConfigSubRequest<SnodeNamespaces.ClosedGroupInfo> {
  constructor(
    args: Omit<
      ConstructorParameters<typeof StoreGroupConfigSubRequest>[0],
      'namespace'
    >
  ) {
    super({ ...args, namespace: SnodeNamespaces.ClosedGroupInfo });
  }
}
export class StoreGroupMembersSubRequest extends StoreGroupConfigSubRequest<SnodeNamespaces.ClosedGroupMembers> {
  constructor(
    args: Omit<
      ConstructorParameters<typeof StoreGroupConfigSubRequest>[0],
      'namespace'
    >
  ) {
    super({ ...args, namespace: SnodeNamespaces.ClosedGroupMembers });
  }
}
export class StoreGroupKeysSubRequest extends StoreGroupConfigSubRequest<SnodeNamespaces.ClosedGroupKeys> {
  constructor(
    args: Omit<
      ConstructorParameters<typeof StoreGroupConfigSubRequest>[0],
      'namespace'
    >
  ) {
    super({ ...args, namespace: SnodeNamespaces.ClosedGroupKeys });
  }
}

export class StoreGroupRevokedRetrievableSubRequest extends StoreGroupConfigSubRequest<SnodeNamespaces.ClosedGroupRevokedRetrievableMessages> {
  constructor(
    args: Omit<
      ConstructorParameters<typeof StoreGroupConfigSubRequest>[0],
      'namespace'
    >
  ) {
    super({
      ...args,
      namespace: SnodeNamespaces.ClosedGroupRevokedRetrievableMessages,
    });
  }
}

export class StoreUserConfigSubRequest extends StoreSubRequest<PubkeyType> {
  private readonly namespace: SnodeNamespacesUserConfig;
  private readonly ttlMs: number;
  private readonly encryptedData: Uint8Array;
  private readonly userSigner: UserSigner;

  constructor(
    args: WithGetNow &
      WithSessionID &
      WithUserSigner & {
        namespace: SnodeNamespacesUserConfig;
        ttlMs: number;
        encryptedData: Uint8Array;
      }
  ) {
    super({ ...args, destination: args.sessionId });
    this.userSigner = args.userSigner;

    this.namespace = args.namespace;
    this.ttlMs = args.ttlMs;
    this.encryptedData = args.encryptedData;

    if (isEmpty(this.encryptedData)) {
      throw new Error('this.encryptedData cannot be empty');
    }

    if (isEmpty(this.destination)) {
      throw new Error('this.destination cannot be empty');
    }
  }

  public async build(): Promise<{
    method: 'store';
    params: StoreOnNodeNormalParams;
  }> {
    const encryptedDataBase64 = fromUInt8ArrayToBase64(this.encryptedData);

    const signDetails = this.userSigner.getSnodeSignatureParams({
      method: this.method,
      namespace: this.namespace,
      getNow: this.getNow,
    });

    return {
      method: this.method,
      params: {
        namespace: this.namespace,
        ttl: this.ttlMs,
        data: encryptedDataBase64,
        ...signDetails,
      },
    };
  }

  public loggingId(): string {
    return `${this.method}-${shortenPk(
      this.destination
    )}-${SnodeNamespace.toRole(this.namespace)}`;
  }
}

/**
 * A request to send a message to the default namespace of another user (namespace 0 is not authenticated)
 */
export class StoreUserMessageSubRequest extends StoreSubRequest<PubkeyType> {
  private readonly ttlMs: number;
  private readonly encryptedData: Uint8Array;
  private readonly namespace = SnodeNamespaces.Default;
  private readonly dbMessageIdentifier: string | null;
  private readonly createdAtNetworkTimestamp: number;
  private readonly plainTextBuffer: Uint8Array | null;

  constructor(
    args: WithCreatedAtNetworkTimestamp &
      WithGetNow &
      WithSessionID & {
        ttlMs: number;
        encryptedData: Uint8Array;
        dbMessageIdentifier: string | null;
        /**
         * When we send a message to a 1o1 recipient, we then need to send the same message to our own swarm as a synced message.
         * To forward that message, we need the original message data, which is the plainTextBuffer field here.
         */
        plainTextBuffer: Uint8Array | null;
      }
  ) {
    super({ ...args, destination: args.sessionId });

    this.ttlMs = args.ttlMs;
    this.encryptedData = args.encryptedData;
    this.plainTextBuffer = args.plainTextBuffer;
    this.dbMessageIdentifier = args.dbMessageIdentifier;
    this.createdAtNetworkTimestamp = args.createdAtNetworkTimestamp;

    if (isEmpty(this.encryptedData)) {
      throw new Error('this.encryptedData cannot be empty');
    }
    if (this.plainTextBuffer && !this.plainTextBuffer.length) {
      throw new Error('this.plainTextBuffer can be either null or non-empty');
    }
  }

  public async build(): Promise<{
    method: 'store';
    params: StoreOnNodeNormalParams;
  }> {
    const encryptedDataBase64 = fromUInt8ArrayToBase64(this.encryptedData);

    return {
      method: this.method,
      params: {
        pubkey: this.destination,
        timestamp: this.getNow(),
        namespace: this.namespace,
        ttl: this.ttlMs,
        data: encryptedDataBase64,
      },
    };
  }

  public loggingId(): string {
    return `${this.method}-${shortenPk(
      this.destination
    )}-${SnodeNamespace.toRole(this.namespace)}`;
  }
}

/**
 * When sending group libsession push(), we can also include extra messages to store (update messages, supplemental keys, etc)
 */
export type StoreGroupExtraData = {
  networkTimestamp: number;
  data: Uint8Array;
  ttl: number;
  pubkey: GroupPubkeyType;
  dbMessageIdentifier: string | null;
} & {
  namespace: SnodeNamespacesGroupConfig | SnodeNamespaces.ClosedGroupMessages;
};

/**
 * STORE SUB REQUESTS
 */
type StoreOnNodeNormalParams = {
  pubkey: string;
  ttl: number;
  timestamp: number;
  data: string;
  namespace: number;
  signature?: string;
  pubkey_ed25519?: string;
};

type StoreOnNodeSubAccountParams = Pick<
  StoreOnNodeNormalParams,
  'data' | 'namespace' | 'ttl' | 'timestamp'
> &
  WithSignature & {
    pubkey: GroupPubkeyType;
    subaccount: string;
    subaccount_sig: string;
    namespace: SnodeNamespaces.ClosedGroupMessages; // this can only be this one, sub accounts holder can not post to something else atm
    // signature is mandatory for sub account
  };

type StoreOnNodeParams = StoreOnNodeNormalParams | StoreOnNodeSubAccountParams;

export type MethodBatchType = 'batch' | 'sequence';
export type WithMethodBatchType = { method: MethodBatchType };

export type RawSnodeSubRequests =
  | RetrieveUserSubRequest
  | RetrieveGroupSubRequest
  | StoreGroupInfoSubRequest
  | StoreGroupMembersSubRequest
  | StoreGroupKeysSubRequest
  | StoreGroupMessageSubRequest
  | StoreGroupRevokedRetrievableSubRequest
  | StoreUserConfigSubRequest
  | SwarmForSubRequest
  | OnsResolveSubRequest
  | GetServiceNodesSubRequest
  | StoreUserMessageSubRequest
  | NetworkTimeSubRequest
  | DeleteHashesFromGroupNodeSubRequest
  | DeleteHashesFromUserNodeSubRequest
  | DeleteAllFromUserNodeSubRequest
  | UpdateExpiryOnNodeUserSubRequest
  | UpdateExpiryOnNodeGroupSubRequest
  | SubaccountRevokeSubRequest
  | SubaccountUnrevokeSubRequest
  | GetExpiriesFromNodeSubRequest
  | DeleteAllFromGroupMsgNodeSubRequest
  | DeleteAllFromGroupNodeSubRequest;

export type BuiltSnodeSubRequests = AwaitedReturn<RawSnodeSubRequests['build']>;

export function builtRequestToLoggingId(
  request: BuiltSnodeSubRequests,
  us?: PubkeyType
): string {
  const { method, params } = request;
  switch (method) {
    case 'info':
    case 'oxend_request':
      return `${method}`;

    case 'get_expiries':
    case 'delete':
    case 'get_swarm':
    case 'revoke_subaccount':
    case 'unrevoke_subaccount':
      return `${method}-${
        params.pubkey === us ? 'us' : shortenPk(params.pubkey)
      }`;

    case 'expire': {
      return `${method}-${
        params.pubkey === us ? 'us' : shortenPk(params.pubkey)
      }`;
    }
    case 'delete_all': {
      return `${method}-${
        params.pubkey === us ? 'us' : shortenPk(params.pubkey)
      }-${
        isString(params.namespace)
          ? params.namespace
          : SnodeNamespace.toRole(params.namespace)
      }}`;
    }
    case 'retrieve':
      return `${method}-${
        params.pubkey === us ? 'us' : shortenPk(params.pubkey)
      }-${SnodeNamespace.toRole(params.namespace)}`;
    case 'store': {
      return `${method}-${
        params.pubkey === us ? 'us' : shortenPk(params.pubkey)
      }-${SnodeNamespace.toRole(params.namespace)}`;
    }
    default:
      assertUnreachable(method, 'should be unreachable case');
      throw new Error('should be unreachable case');
  }
}

export const MAX_SUB_REQUESTS_COUNT = 20;

export type BatchStoreWithExtraParams =
  | StoreOnNodeParams
  | DeleteHashesFromGroupNodeSubRequest
  | DeleteHashesFromUserNodeSubRequest
  | SubaccountRevokeSubRequest
  | SubaccountUnrevokeSubRequest;

/**
 * A `StoreUserInitiatedSubRequest` is a request that the user made and that (potentially) has
 * a corresponding message in the database.
 * Those messages are the messages that display a failed/sent status, so we need to update them when the request is done, to reflect the
 * success/failure of the sending step.
 */
export type StoreUserInitiatedSubRequest =
  | StoreGroupMessageSubRequest
  | StoreUserMessageSubRequest;

export function isStoreUserInitiatedSubRequest(
  request: SnodeAPISubRequest<string>
): request is StoreUserInitiatedSubRequest {
  return (
    request instanceof StoreGroupMessageSubRequest ||
    request instanceof StoreUserMessageSubRequest
  );
}
