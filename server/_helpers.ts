// Copyright (C) 2020 Russell Clarey. All rights reserved. MIT license.

import {
  ServerRequest as HttpRequest,
} from "https://deno.land/std@0.90.0/http/mod.ts#^";

import { bencode } from "../bencode.ts";
import { spreadUint8Array, writeInt } from "../_bytes.ts";

export function sendHttpError(
  httpRequest: HttpRequest,
  reason: string,
): Promise<void> {
  const te = new TextEncoder();
  const body = bencode({
    "failure reason": te.encode(reason),
  });
  return httpRequest.respond({ body });
}
