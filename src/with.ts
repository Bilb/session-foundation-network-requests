import type {
  GroupPubkeyType,
  PubkeyType,
  Uint8ArrayLen100,
} from '@session-foundation/basic-types';

export type WithMessageHash = { messageHash: string };
export type WithMessageHashOrNull = { messageHash: string | null };
export type WithTimestamp = { timestamp: number };
export type WithSignature = { signature: string };
export type WithSecretKey = { secretKey: Uint8Array };

export type WithMaxSize = { max_size?: number };
export type WithCreatedAtNetworkTimestamp = {
  createdAtNetworkTimestamp: number;
};
export type WithMethod<T extends string> = { method: T };
export type WithDestination<T extends PubkeyType | GroupPubkeyType> = {
  destination: T;
};
export type WithBatchMethod<T extends string> = { method: T };
export type WithGetNow = { getNow: () => number };

export type ShortenOrExtend = 'extend' | 'shorten' | '';
export type WithShortenOrExtend = { shortenOrExtend: ShortenOrExtend };
export type WithMessagesHashes = { messagesHashes: Array<string> };
export type WithAdminSecretKey = { adminSecretKey: Uint8Array };
export type WithAuthData = { authData: Uint8ArrayLen100 };
