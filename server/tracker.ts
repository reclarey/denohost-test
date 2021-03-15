// Copyright (C) 2020 Russell Clarey. All rights reserved. MIT license.

import {
  serve as serveHttp,
  Server as HttpServer,
  ServerRequest as HttpRequest,
} from "https://deno.land/std@0.90.0/http/mod.ts#^";
import { MuxAsyncIterator } from "https://deno.land/std@0.90.0/async/mux_async_iterator.ts#^";
import { equals } from "https://deno.land/std@0.90.0/bytes/mod.ts#^";

import {
  AnnounceEvent,
  AnnounceInfo,
  CompactValue,
  PeerInfo,
  PeerState,
  ScrapeData,
} from "../types.ts";
import { bencode } from "../bencode.ts";
import { sendHttpError } from "./_helpers.ts";
import {
  readBigInt,
  readInt,
  spreadUint8Array,
  writeInt,
  decodeBinaryData,
} from "../_bytes.ts";

const CONNECT_MAGIC = 0x41727101980n;
const DEFAULT_WANT = 50;
const DEFAULT_INTERVAL = 600; // 10min

export abstract class AnnounceRequest implements AnnounceInfo {
  /** SHA1 hash of the bencoded info dictionary */
  infoHash!: Uint8Array;
  /** Self-selected ID */
  peerId!: Uint8Array;
  /**  The IP address at which the client is listening */
  ip!: string;
  /** The port at which the client is listening */
  port!: number;
  /** Number of bytes uploaded */
  uploaded!: bigint;
  /** Number of bytes downloaded */
  downloaded!: bigint;
  /** Number of bytes the client still has to download */
  left!: bigint;
  /** Indicates the purpose of the request */
  event!: AnnounceEvent;
  /** Number of peers that the client would like to receive from the tracker */
  numWant!: number;
  /** Number of seconds to advise clients wait between regular requests */
  interval!: number;
  /** Indicates whether or not the client accepts a compact response */
  compact?: CompactValue;
  /** Send a list of peers to the requesting client */
  abstract respond(peers: PeerInfo[]): Promise<void>;
  /** Send a failure response to the requesting client */
  abstract reject(reason: string): Promise<void>;
}

export interface HttpAnnounceParams extends AnnounceInfo {
  /** Number of peers that the client would like to receive from the tracker */
  numWant: number;
  /** Number of seconds to advise clients wait between regular requests */
  interval: number;
  /** Indicates whether or not the client accepts a compact response */
  compact: CompactValue;
  /** The underlying HTTP request */
  httpRequest: HttpRequest;
}

function countPeers(peers: PeerInfo[]): [number, number] {
  return peers.reduce((counts, { state }) => {
    counts[state === PeerState.seeder ? 0 : 1] += 1;
    return counts;
  }, [0, 0]);
}

export class HttpAnnounceRequest extends AnnounceRequest {
  /** Indicates whether or not the client accepts a compact response */
  compact!: CompactValue;
  /** The underlying HTTP request */
  httpRequest!: HttpRequest;
  /**
   * An addition ID meant to allow a client to prove their identity should their IP
   * address change
   */
  key?: Uint8Array;

  constructor(fields: HttpAnnounceParams) {
    super();
    Object.assign(this, fields);
  }

  /** Send a list of peers to the requesting client */
  respond(peers: PeerInfo[]): Promise<void> {
    try {
      const te = new TextEncoder();
      const [complete, incomplete] = countPeers(peers);

      let body: Uint8Array;
      if (this.compact === CompactValue.compact) {
        const compactPeers = new Uint8Array(6 * peers.length);
        for (const [i, peer] of peers.entries()) {
          const [p1, p2, p3, p4] = peer.ip.split(".");
          compactPeers[6 * i] = Number(p1);
          compactPeers[6 * i + 1] = Number(p2);
          compactPeers[6 * i + 2] = Number(p3);
          compactPeers[6 * i + 3] = Number(p4);
          compactPeers[6 * i + 4] = Number((peer.port / 256) | 0);
          compactPeers[6 * i + 5] = Number(peer.port % 256);
        }
        body = bencode({
          complete,
          incomplete,
          interval: this.interval,
          peers: compactPeers,
        });
      } else {
        body = bencode({
          complete,
          incomplete,
          interval: this.interval,
          peers: peers.map(({ port, id, ip }) => ({
            ip: te.encode(ip),
            "peer id": id,
            port,
          })),
        });
      }

      return this.httpRequest.respond({ body });
    } catch {
      return this.reject("internal error");
    }
  }

  /** Send a failure response to the requesting client */
  reject(reason: string): Promise<void> {
    return sendHttpError(this.httpRequest, reason);
  }
}

type ScrapeInfo = {
  complete: number;
  downloaded: number;
  incomplete: number;
};

export abstract class ScrapeRequest {
  /** Requested info hashes */
  infoHashes!: Uint8Array[];
  /** Send aggregate info to the requesting client */
  abstract respond(list: ScrapeData[]): Promise<void>;
  /** Send a failure response to the requesting client */
  abstract reject(reason: string): Promise<void>;
}

export class HttpScrapeRequest extends ScrapeRequest {
  /**
   * @param httpRequest - The underlying HTTP request
   * @param infoHashes - Requested info hashes
   */
  constructor(
    public httpRequest: HttpRequest,
    public infoHashes: Uint8Array[],
  ) {
    super();
  }

  /** Send aggregate info to the requesting client */
  respond(list: ScrapeData[]): Promise<void> {
    try {
      const files = new Map<Uint8Array, ScrapeInfo>(
        list.map((
          { infoHash, ...rest },
        ) => [infoHash, rest]),
      );
      const body = bencode({ files });
      return this.httpRequest.respond({ body });
    } catch {
      return this.reject("internal error");
    }
  }

  /** Send a failure response to the requesting client */
  reject(reason: string): Promise<void> {
    return sendHttpError(this.httpRequest, reason);
  }
}

interface ParsedParams {
  ip: string;
  params: URLSearchParams;
  infoHashes: Uint8Array[];
  peerId: Uint8Array | null;
  key: Uint8Array | null;
}

function parseParams(
  req: HttpRequest,
): ParsedParams {
  let peerId: Uint8Array | null = null;
  let key: Uint8Array | null = null;
  const infoHashes: Uint8Array[] = [];
  const queryStr = req.url.replace(/[^?]*\?/, "").replace(
    /(?:^|&)info_hash=([^&]+)/g,
    (_, hash) => {
      infoHashes.push(decodeBinaryData(hash));
      return "&";
    },
  ).replace(/(?:^|&)peer_id=([^&]+)/g, (_, id) => {
    peerId = decodeBinaryData(id);
    return "&";
  }).replace(/(?:^|&)key=([^&]+)/g, (_, key) => {
    key = decodeBinaryData(key);
    return "&";
  });

  let ip = (req.conn.remoteAddr as Deno.NetAddr).hostname;
  if (req.headers.has("X-Forwarded-For")) {
    ip = req.headers.get("X-Forwarded-For")!.split(", ")[0];
  }

  return {
    params: new URLSearchParams(queryStr),
    ip,
    infoHashes,
    peerId,
    key,
  };
}

function validateAnnounceParams(
  { ip, params, peerId, infoHashes, key }: ParsedParams,
): AnnounceInfo | null {
  if (
    peerId === null ||
    infoHashes.length !== 1 ||
    !params.has("port") ||
    !params.has("uploaded") ||
    !params.has("downloaded") ||
    !params.has("left")
  ) {
    return null;
  }

  const maybeEvent = params.get("event");
  const maybeNumWant = params.get("num_want");
  const maybeCompact = params.get("compact");
  return {
    peerId,
    infoHash: infoHashes[0],
    ip: params.get("ip") ?? ip,
    port: Number(params.get("port")!),
    uploaded: BigInt(params.get("uploaded")!),
    downloaded: BigInt(params.get("downloaded")!),
    left: BigInt(params.get("left")!),
    event: maybeEvent && ![...Object.keys(AnnounceEvent)].includes(maybeEvent)
      ? maybeEvent as AnnounceEvent
      : AnnounceEvent.empty,
    numWant: maybeNumWant !== null ? Number(maybeNumWant) : undefined,
    compact: maybeCompact !== null ? maybeCompact as CompactValue : undefined,
    key: key ?? undefined,
  };
}

export type TrackerRequest =
  | HttpAnnounceRequest
  | HttpScrapeRequest;

export interface ServerParams {
  /** Underlying HTTP server */
  httpServer?: HttpServer;
  /** Number of seconds to advise clients wait between regular requests */
  interval: number;
  /** List of allowed info hashes. If undefined then accept all incoming info hashes */
  filterList?: Uint8Array[];
}

export class TrackerServer implements AsyncIterable<TrackerRequest> {
  /** Set of connection IDs currently in use by UDP connections */
  connectionIds: Set<bigint>;
  /** Number of seconds to advise clients wait between regular requests */
  interval!: number;
  /** List of allowed info hashes. If undefined then accept all incoming info hashes */
  filterList?: Uint8Array[];
  /** Underlying HTTP server */
  httpServer?: HttpServer;

  constructor(params: ServerParams) {
    this.connectionIds = new Set<bigint>();
    Object.assign(this, params);
  }

  private filteredHash(infoHash: Uint8Array): boolean {
    if (!this.filterList) {
      return false;
    }
    return !this.filterList.find((x) => equals(x, infoHash));
  }

  private async *iterateHttpRequests(): AsyncIterableIterator<
    HttpAnnounceRequest | HttpScrapeRequest
  > {
    for await (const httpRequest of this.httpServer!) {
      try {
        const match = httpRequest.url.match(/\/(announce|scrape|stats)\??/);
        if (!match) {
          // ignore
          continue;
        }

        const parsed = parseParams(httpRequest);

        if (match[1] === "announce") {
          const valid = validateAnnounceParams(parsed);

          if (valid === null) {
            sendHttpError(httpRequest, "bad announce parameters");
            continue;
          }

          if (this.filteredHash(valid.infoHash)) {
            sendHttpError(
              httpRequest,
              "info_hash is not in the list of supported info hashes",
            );
            continue;
          }

          yield new HttpAnnounceRequest({
            httpRequest,
            interval: this.interval,
            ...valid,
            compact: valid.compact ?? CompactValue.full,
            numWant: valid.numWant ?? DEFAULT_WANT,
          });
        } else if (match[1] === "scrape") {
          yield new HttpScrapeRequest(
            httpRequest,
            parsed.infoHashes,
          );
        } else {
          // TODO
        }
      } catch (e) {
        // TODO log or something
        console.log(e);
      }
    }
  }

  [Symbol.asyncIterator](): AsyncIterableIterator<TrackerRequest> {
    return this.iterateHttpRequests();
  }
}

export interface ServeOptions {
  /** HTTP server options */
  http?: {
    disable?: boolean;
    port?: number;
  };
  /** List of allowed info hashes. If undefined then accept all incoming info hashes */
  filterList?: Uint8Array[];
  /** Number of seconds to advise clients wait between regular requests. Defaults to 60 */
  interval?: number;
}

/** Create a tracker server */
export function serveTracker(opts: ServeOptions = {}): TrackerServer {
  let httpServer: HttpServer | undefined;
  if (opts.http?.disable !== true) {
    httpServer = serveHttp({ port: opts.http?.port ?? 80 });
  }

  const server = new TrackerServer({
    httpServer,
    filterList: opts.filterList,
    interval: opts.interval ?? DEFAULT_INTERVAL,
  });

  return server;
}
