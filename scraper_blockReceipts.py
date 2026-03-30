"""
Install:
  pip install psycopg[binary] requests eth-utils pyyaml python-dotenv

Env:
  ETH_RPC_URL
  PG_DSN
  BLOCK_CHUNK    default 1000   # how many blocks processed per outer loop
  BLOCK_BATCH    default 200    # how many eth_getBlockByNumber / eth_getBlockReceipts calls per JSON-RPC batch
  RPC_TIMEOUT    default 60

Usage:
  python scraper_blockReceipts.py --start 18000000 --end 18005000
  python scraper_blockReceipts.py --start 18000000 --end 18005000 --chunk 500 --block-batch 100
  python scraper_blockReceipts.py --start 18000000 --yaml config/stablecoins_detailed.yaml
"""

# good default: 1st of December 00:00:00 - 4652925

import os
import time
import argparse
from typing import Any, Dict, Iterable, List, Optional, Tuple, Set

import requests
import psycopg
import yaml
from eth_utils import keccak
from dotenv import load_dotenv

load_dotenv()


# ---------------- RPC CLIENT (raw JSON-RPC) ---------------- #

class RpcClient:
    def __init__(self, url: str, timeout: int = 60, max_retries: int = 6):
        self.url = url
        self.session = requests.Session()
        self.timeout = timeout
        self.max_retries = max_retries
        self._id = 0

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _post(self, payload: Any) -> Any:
        last = None
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self.session.post(self.url, json=payload, timeout=self.timeout)
                resp.raise_for_status()
                return resp.json()
            except Exception as e:
                last = e
                time.sleep(min(2 ** (attempt - 1), 20))
        raise RuntimeError(f"RPC request failed after retries: {last}") from last

    def call(self, method: str, params: list) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
            "params": params,
        }
        data = self._post(payload)
        if isinstance(data, dict) and "error" in data:
            raise RuntimeError(f"RPC error: {data['error']}")
        return data["result"]

    def batch(self, calls: List[Tuple[str, list]]) -> List[Any]:
        """
        calls: [(method, params), ...]
        returns results in the same order
        """
        payload = []
        ids: List[int] = []
        for method, params in calls:
            cid = self._next_id()
            ids.append(cid)
            payload.append({
                "jsonrpc": "2.0",
                "id": cid,
                "method": method,
                "params": params,
            })

        data = self._post(payload)
        if not isinstance(data, list):
            raise RuntimeError(f"Expected batch response list, got {type(data)}")

        by_id = {item["id"]: item for item in data}
        out: List[Any] = []
        for cid in ids:
            item = by_id.get(cid)
            if item is None:
                raise RuntimeError(f"Missing batch response for id={cid}")
            if "error" in item:
                raise RuntimeError(f"RPC error for id={cid}: {item['error']}")
            out.append(item.get("result"))
        return out

    def eth_block_number(self) -> int:
        return int(self.call("eth_blockNumber", []), 16)

    def eth_get_block_by_number_batch(self, block_numbers: List[int], full_tx: bool = True) -> List[dict]:
        calls = [("eth_getBlockByNumber", [hex(bn), full_tx]) for bn in block_numbers]
        return self.batch(calls)

    def eth_get_block_receipts_batch(self, block_numbers: List[int]) -> List[List[dict]]:
        calls = [("eth_getBlockReceipts", [hex(bn)]) for bn in block_numbers]
        return self.batch(calls)


# ---------------- helpers (hex parsing) ---------------- #

def h2i(x: Any) -> int:
    return int(x, 16) if isinstance(x, str) and x.startswith("0x") else int(x)

def hex_to_bytes20(addr_hex: Optional[str]) -> Optional[bytes]:
    if addr_hex is None:
        return None
    h = addr_hex[2:] if addr_hex.startswith("0x") else addr_hex
    b = bytes.fromhex(h)
    if len(b) != 20:
        raise ValueError(f"expected 20-byte address, got {len(b)} bytes: {addr_hex}")
    return b

def topic_to_addr(topic_hex: str) -> bytes:
    h = topic_hex[2:] if topic_hex.startswith("0x") else topic_hex
    t = bytes.fromhex(h)
    if len(t) != 32:
        raise ValueError("topic not 32 bytes")
    return t[-20:]

def method_id_from_input(input_hex: Optional[str], to_addr: Optional[bytes]) -> Optional[bytes]:
    if to_addr is None:
        return None
    if not input_hex or input_hex == "0x":
        return None
    h = input_hex[2:] if input_hex.startswith("0x") else input_hex
    if len(h) < 8:
        return None
    return bytes.fromhex(h[:8])

def uint256_from_data(data_hex: str, word_index: int = 0) -> int:
    h = data_hex[2:] if data_hex.startswith("0x") else data_hex
    if not h:
        return 0
    start = word_index * 64
    end = start + 64
    if len(h) < end:
        raise ValueError(f"data too short for uint256 word {word_index}")
    return int(h[start:end], 16)

def topic0(sig: str) -> str:
    return "0x" + keccak(text=sig).hex()

def safe_int_hex(x: Any) -> Optional[int]:
    if x is None:
        return None
    return int(x, 16) if isinstance(x, str) and x.startswith("0x") else int(x)

def hex_to_int_default0(x: Optional[str]) -> int:
    if not x or x == "0x":
        return 0
    return int(x, 16)


# ---------------- event signatures & mapping ---------------- #

TRANSFER_SIG = "Transfer(address,address,uint256)"
TRANSFER_TOPIC0 = topic0(TRANSFER_SIG)

EV_ISSUE = 2
EV_REDEEM = 3
EV_ADDED_BLACKLIST = 4
EV_REMOVED_BLACKLIST = 5
EV_DESTROYED_BLACK_FUNDS = 6

DEFAULT_SPECIAL_SIGS = [
    "Blacklisted(address)",
    "UnBlacklisted(address)",
    "AddedBlackList(address)",
    "RemovedBlackList(address)",
    "DestroyedBlackFunds(address,uint256)",
    "Issue(uint256)",
    "Redeem(uint256)",
    "Mint(address,address,uint256)",
    "Burn(address,uint256)",
    "FRAXMinted(address,address,uint256)",
    "FRAXBurned(address,address,uint256)",
]

SIG_TO_EVENTTYPE = {
    "Issue(uint256)": EV_ISSUE,
    "Mint(address,address,uint256)": EV_ISSUE,
    "FRAXMinted(address,address,uint256)": EV_ISSUE,

    "Redeem(uint256)": EV_REDEEM,
    "Burn(address,uint256)": EV_REDEEM,
    "FRAXBurned(address,address,uint256)": EV_REDEEM,

    "AddedBlackList(address)": EV_ADDED_BLACKLIST,
    "Blacklisted(address)": EV_ADDED_BLACKLIST,

    "RemovedBlackList(address)": EV_REMOVED_BLACKLIST,
    "UnBlacklisted(address)": EV_REMOVED_BLACKLIST,

    "DestroyedBlackFunds(address,uint256)": EV_DESTROYED_BLACK_FUNDS,
}

def load_sigs_from_yaml(path: Optional[str]) -> List[str]:
    """
    Uses the stablecoins YAML only as a source of signatures.
    Still NO address filtering.
    """
    if not path:
        return []
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    sigs: List[str] = []
    for _, cfg in (raw.get("stablecoins", {}) or {}).items():
        events = (cfg.get("events", {}) or {})
        for ev_name, ev_cfg in events.items():
            if ev_name in ("transfer", "mint_burn_via_zero"):
                continue
            sig = ev_cfg.get("signature")
            if sig and sig not in sigs:
                sigs.append(sig)
    return sigs


# ---------------- DB schema ---------------- #

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS eth_block (
  block_number   INTEGER PRIMARY KEY,
  ts             TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS address (
  id      SERIAL PRIMARY KEY,
  addr    BYTEA UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS token (
  id      SERIAL PRIMARY KEY,
  addr    BYTEA UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS eth_tx (
  block_number         INTEGER NOT NULL REFERENCES eth_block(block_number),
  tx_index             INTEGER NOT NULL,
  from_id              INTEGER NOT NULL REFERENCES address(id),
  to_id                INTEGER REFERENCES address(id),
  method_id            BYTEA,
  value                NUMERIC(78,0) NOT NULL DEFAULT 0,
  gas_price            NUMERIC(78,0),
  gas_used             BIGINT,
  effective_gas_price  NUMERIC(78,0),
  success              BOOLEAN,
  PRIMARY KEY (block_number, tx_index)
);

CREATE TABLE IF NOT EXISTS erc20_transfer (
  block_number   INTEGER NOT NULL,
  tx_index       INTEGER NOT NULL,
  log_index      INTEGER NOT NULL,
  token_id       INTEGER NOT NULL REFERENCES token(id),
  from_id        INTEGER NOT NULL REFERENCES address(id),
  to_id          INTEGER NOT NULL REFERENCES address(id),
  amount         NUMERIC(78,0) NOT NULL,
  PRIMARY KEY (block_number, tx_index, log_index),
  FOREIGN KEY (block_number, tx_index) REFERENCES eth_tx(block_number, tx_index)
);

CREATE TABLE IF NOT EXISTS token_event (
  block_number   INTEGER NOT NULL,
  tx_index       INTEGER NOT NULL,
  log_index      INTEGER NOT NULL,
  token_id       INTEGER NOT NULL REFERENCES token(id),
  event_type     SMALLINT NOT NULL,
  a0_id          INTEGER REFERENCES address(id),
  a1_id          INTEGER REFERENCES address(id),
  value          NUMERIC(78,0),
  PRIMARY KEY (block_number, tx_index, log_index),
  FOREIGN KEY (block_number, tx_index) REFERENCES eth_tx(block_number, tx_index)
);
"""

MIGRATION_SQL = """
ALTER TABLE eth_tx ADD COLUMN IF NOT EXISTS value NUMERIC(78,0) NOT NULL DEFAULT 0;
ALTER TABLE eth_tx ADD COLUMN IF NOT EXISTS gas_price NUMERIC(78,0);
ALTER TABLE eth_tx ADD COLUMN IF NOT EXISTS gas_used BIGINT;
ALTER TABLE eth_tx ADD COLUMN IF NOT EXISTS effective_gas_price NUMERIC(78,0);
ALTER TABLE eth_tx ADD COLUMN IF NOT EXISTS success BOOLEAN;
"""

def ensure_schema(conn: psycopg.Connection) -> None:
    with conn.cursor() as cur:
        cur.execute(SCHEMA_SQL)
        cur.execute(MIGRATION_SQL)
    conn.commit()


# ---------------- upserts ---------------- #

def upsert_addresses(conn: psycopg.Connection, addrs: Iterable[Optional[bytes]]) -> Dict[bytes, int]:
    addr_set: Set[bytes] = {a for a in addrs if a is not None}
    if not addr_set:
        return {}

    addr_list = list(addr_set)

    with conn.cursor() as cur:
        cur.executemany(
            "INSERT INTO address(addr) VALUES (%s) ON CONFLICT (addr) DO NOTHING",
            [(a,) for a in addr_list],
        )
        cur.execute(
            "SELECT id, addr FROM address WHERE addr = ANY(%s)",
            (addr_list,),
        )
        rows = cur.fetchall()

    conn.commit()
    return {addr: _id for (_id, addr) in rows}

def upsert_tokens(conn: psycopg.Connection, addrs: Iterable[Optional[bytes]]) -> Dict[bytes, int]:
    token_set = {a for a in addrs if a is not None}
    if not token_set:
        return {}

    token_list = list(token_set)

    with conn.cursor() as cur:
        cur.executemany(
            "INSERT INTO token(addr) VALUES (%s) ON CONFLICT (addr) DO NOTHING",
            [(a,) for a in token_list],
        )
        cur.execute(
            "SELECT id, addr FROM token WHERE addr = ANY(%s)",
            (token_list,),
        )
        rows = cur.fetchall()

    conn.commit()
    return {addr: _id for (_id, addr) in rows}


# ---------------- parsing ---------------- #

def parse_special_events(
    lg: dict,
    topic0_to_sig: Dict[str, str]
) -> Optional[Tuple[int, int, int, bytes, int, Optional[bytes], Optional[bytes], Optional[int]]]:
    """
    Parses special logs from receipt logs.
    """
    topics = lg.get("topics") or []
    if not topics:
        return None

    t0 = topics[0].lower()
    sig = topic0_to_sig.get(t0)
    if not sig:
        return None

    event_type = SIG_TO_EVENTTYPE.get(sig)
    if not event_type:
        return None

    bn = h2i(lg["blockNumber"])
    txi = h2i(lg["transactionIndex"])
    logi = h2i(lg["logIndex"])
    token = hex_to_bytes20(lg["address"])
    data_hex = lg.get("data") or "0x"

    a0: Optional[bytes] = None
    a1: Optional[bytes] = None
    value: Optional[int] = None

    if sig in ("Issue(uint256)", "Redeem(uint256)"):
        value = uint256_from_data(data_hex, 0)
        return (bn, txi, logi, token, event_type, a0, a1, value)

    if sig == "DestroyedBlackFunds(address,uint256)":
        if len(topics) >= 2 and topics[1] and len(topics[1]) >= 66:
            a0 = topic_to_addr(topics[1])
            value = uint256_from_data(data_hex, 0)
        else:
            h = data_hex[2:] if data_hex.startswith("0x") else data_hex
            if len(h) < 128:
                return None
            a0 = bytes.fromhex(h[:64][-40:])
            value = uint256_from_data(data_hex, 1)
        return (bn, txi, logi, token, event_type, a0, a1, value)

    if sig in (
        "Blacklisted(address)",
        "UnBlacklisted(address)",
        "AddedBlackList(address)",
        "RemovedBlackList(address)",
    ):
        if len(topics) >= 2 and topics[1] and len(topics[1]) >= 66:
            a0 = topic_to_addr(topics[1])
            return (bn, txi, logi, token, event_type, a0, a1, value)

        h = data_hex[2:] if data_hex.startswith("0x") else data_hex
        if len(h) >= 64:
            a0 = bytes.fromhex(h[:64][-40:])
            return (bn, txi, logi, token, event_type, a0, a1, value)
        return None

    if sig in ("Mint(address,address,uint256)", "FRAXMinted(address,address,uint256)"):
        if len(topics) >= 3:
            a0 = topic_to_addr(topics[1])
            a1 = topic_to_addr(topics[2])
        value = uint256_from_data(data_hex, 0)
        return (bn, txi, logi, token, event_type, a0, a1, value)

    if sig == "Burn(address,uint256)":
        if len(topics) >= 2:
            a0 = topic_to_addr(topics[1])
        value = uint256_from_data(data_hex, 0)
        return (bn, txi, logi, token, event_type, a0, a1, value)

    if sig == "FRAXBurned(address,address,uint256)":
        if len(topics) >= 3:
            a0 = topic_to_addr(topics[1])
            a1 = topic_to_addr(topics[2])
        value = uint256_from_data(data_hex, 0)
        return (bn, txi, logi, token, event_type, a0, a1, value)

    return None


# ---------------- inserts ---------------- #

def insert_blocks_and_txs(
    conn: psycopg.Connection,
    blocks: List[dict],
    receipts_by_block: Dict[int, List[dict]],
) -> None:
    block_rows: List[Tuple[int, int]] = []
    tx_tmp: List[Tuple[
        int, int, bytes, Optional[bytes], Optional[bytes], int, Optional[int], Optional[int], Optional[int], Optional[bool]
    ]] = []
    addr_need: List[Optional[bytes]] = []

    receipt_map: Dict[Tuple[int, int], dict] = {}
    for bn, receipt_list in receipts_by_block.items():
        for rcpt in receipt_list or []:
            r_bn = h2i(rcpt["blockNumber"])
            r_txi = h2i(rcpt["transactionIndex"])
            receipt_map[(r_bn, r_txi)] = rcpt

    for b in blocks:
        if not b:
            continue

        bn = h2i(b["number"])
        ts = h2i(b["timestamp"])
        block_rows.append((bn, ts))

        for tx in b.get("transactions", []):
            tx_index = h2i(tx["transactionIndex"])
            from_addr = hex_to_bytes20(tx["from"])
            to_addr = hex_to_bytes20(tx["to"]) if tx.get("to") else None
            method_id = method_id_from_input(tx.get("input"), to_addr)

            value = hex_to_int_default0(tx.get("value"))
            gas_price = safe_int_hex(tx.get("gasPrice"))

            rcpt = receipt_map.get((bn, tx_index))
            gas_used = safe_int_hex(rcpt.get("gasUsed")) if rcpt else None
            effective_gas_price = safe_int_hex(rcpt.get("effectiveGasPrice")) if rcpt else None

            status_raw = rcpt.get("status") if rcpt else None
            success = None if status_raw is None else (h2i(status_raw) == 1)

            tx_tmp.append((
                bn, tx_index, from_addr, to_addr, method_id,
                value, gas_price, gas_used, effective_gas_price, success,
            ))
            addr_need.extend([from_addr, to_addr])

    addr_id = upsert_addresses(conn, addr_need)

    tx_rows: List[Tuple[
        int, int, int, Optional[int], Optional[bytes], int, Optional[int], Optional[int], Optional[int], Optional[bool]
    ]] = []
    for bn, tx_index, from_addr, to_addr, method_id, value, gas_price, gas_used, effective_gas_price, success in tx_tmp:
        from_id = addr_id[from_addr]
        to_id = addr_id[to_addr] if to_addr is not None else None
        tx_rows.append((
            bn, tx_index, from_id, to_id, method_id,
            value, gas_price, gas_used, effective_gas_price, success,
        ))

    with conn.cursor() as cur:
        if block_rows:
            cur.executemany(
                """
                INSERT INTO eth_block(block_number, ts)
                VALUES (%s, to_timestamp(%s))
                ON CONFLICT (block_number) DO NOTHING
                """,
                block_rows,
            )

        if tx_rows:
            cur.executemany(
                """
                INSERT INTO eth_tx(
                  block_number, tx_index, from_id, to_id, method_id,
                  value, gas_price, gas_used, effective_gas_price, success
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (block_number, tx_index) DO NOTHING
                """,
                tx_rows,
            )

    conn.commit()

def insert_transfer_logs(conn: psycopg.Connection, logs: List[dict]) -> None:
    parsed: List[Tuple[int, int, int, bytes, bytes, bytes, int]] = []
    token_need: List[Optional[bytes]] = []
    addr_need: List[Optional[bytes]] = []

    for lg in logs:
        topics = lg.get("topics") or []
        if len(topics) < 3:
            continue

        bn = h2i(lg["blockNumber"])
        txi = h2i(lg["transactionIndex"])
        logi = h2i(lg["logIndex"])

        token_addr = hex_to_bytes20(lg["address"])
        from_addr = topic_to_addr(topics[1])
        to_addr = topic_to_addr(topics[2])
        #amount = hex_to_int_default0(lg.get("data")) # doesnt work for malformed logs
        data_hex = lg.get("data") or "0x"
        try:
            amount = uint256_from_data(data_hex, 0)
        except Exception:
            print(
                "Skipping malformed transfer log:",
                {
                    "block": lg.get("blockNumber"),
                    "tx": lg.get("transactionIndex"),
                    "log": lg.get("logIndex"),
                    "address": lg.get("address"),
                    "topics_len": len(lg.get("topics") or []),
                    "data_len": len(data_hex[2:] if data_hex.startswith("0x") else data_hex),
                    "data": data_hex[:130],
                }
            )
            continue

        parsed.append((bn, txi, logi, token_addr, from_addr, to_addr, amount))
        token_need.append(token_addr)
        addr_need.extend([from_addr, to_addr])

    if not parsed:
        return

    token_id = upsert_tokens(conn, token_need)
    addr_id = upsert_addresses(conn, addr_need)

    rows: List[Tuple[int, int, int, int, int, int, int]] = []
    for bn, txi, logi, token_addr, from_addr, to_addr, amount in parsed:
        rows.append((
            bn, txi, logi,
            token_id[token_addr],
            addr_id[from_addr],
            addr_id[to_addr],
            amount,
        ))

    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO erc20_transfer
              (block_number, tx_index, log_index, token_id, from_id, to_id, amount)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (block_number, tx_index, log_index) DO NOTHING
            """,
            rows,
        )
    conn.commit()

def insert_token_events(
    conn: psycopg.Connection,
    rows_raw: List[Tuple[int, int, int, bytes, int, Optional[bytes], Optional[bytes], Optional[int]]]
) -> None:
    if not rows_raw:
        return

    token_need: List[Optional[bytes]] = []
    addr_need: List[Optional[bytes]] = []

    for _, _, _, token_addr, _, a0, a1, _ in rows_raw:
        token_need.append(token_addr)
        addr_need.extend([a0, a1])

    token_id = upsert_tokens(conn, token_need)
    addr_id = upsert_addresses(conn, addr_need)

    rows: List[Tuple[int, int, int, int, int, Optional[int], Optional[int], Optional[int]]] = []
    for bn, txi, logi, token_addr, ev_type, a0, a1, value in rows_raw:
        rows.append((
            bn, txi, logi,
            token_id[token_addr],
            ev_type,
            addr_id[a0] if a0 is not None else None,
            addr_id[a1] if a1 is not None else None,
            value,
        ))

    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO token_event
              (block_number, tx_index, log_index, token_id, event_type, a0_id, a1_id, value)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (block_number, tx_index, log_index) DO NOTHING
            """,
            rows,
        )
    conn.commit()


# ---------------- receipt-log extraction ---------------- #

def extract_logs_from_receipts(
    receipts_by_block: Dict[int, List[dict]],
    transfer_topic0: str,
    topic0_to_sig: Dict[str, str],
) -> Tuple[
    List[dict],
    List[Tuple[int, int, int, bytes, int, Optional[bytes], Optional[bytes], Optional[int]]]
]:
    transfer_logs: List[dict] = []
    special_rows: List[Tuple[int, int, int, bytes, int, Optional[bytes], Optional[bytes], Optional[int]]] = []

    special_topic0s = set(topic0_to_sig.keys())
    transfer_topic0_l = transfer_topic0.lower()

    for _, receipt_list in receipts_by_block.items():
        for rcpt in receipt_list or []:
            for lg in rcpt.get("logs", []) or []:
                topics = lg.get("topics") or []
                if not topics:
                    continue

                t0 = topics[0].lower()

                if t0 == transfer_topic0_l:
                    transfer_logs.append(lg)
                    continue

                if t0 in special_topic0s:
                    row = parse_special_events(lg, topic0_to_sig)
                    if row is not None:
                        special_rows.append(row)

    return transfer_logs, special_rows


# ---------------- batched fetch helpers ---------------- #

def fetch_blocks_adaptive(rpc: RpcClient, block_nums: List[int], full_tx: bool, start_batch: int) -> List[dict]:
    """Fetch blocks with adaptive batch size."""
    out = []
    i = 0
    batch = max(1, start_batch)
    max_batch = batch

    while i < len(block_nums):
        chunk = block_nums[i:i + batch]
        try:
            out.extend(rpc.eth_get_block_by_number_batch(chunk, full_tx=full_tx))
            i += batch
            if batch < max_batch:
                batch = min(max_batch, batch * 2)
        except RuntimeError as e:
            msg = str(e).lower()
            if ("response too large" in msg or "timeout" in msg) and batch > 1:
                batch = max(1, batch // 2)
                continue
            raise

    return out

def fetch_block_receipts_adaptive(rpc: RpcClient, block_nums: List[int], start_batch: int) -> List[List[dict]]:
    """Fetch block receipts with adaptive batch size."""
    out: List[List[dict]] = []
    i = 0
    batch = max(1, start_batch)
    max_batch = batch

    while i < len(block_nums):
        chunk = block_nums[i:i + batch]
        try:
            out.extend(rpc.eth_get_block_receipts_batch(chunk))
            i += batch
            if batch < max_batch:
                batch = min(max_batch, batch * 2)
        except RuntimeError as e:
            msg = str(e).lower()
            if ("response too large" in msg or "timeout" in msg) and batch > 1:
                batch = max(1, batch // 2)
                continue
            raise

    return out


# ---------------- main ---------------- #

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default=os.getenv("ETH_RPC_URL"), help="RPC URL (HTTP)")
    ap.add_argument("--pg", default=os.getenv("PG_DSN"), help="Postgres DSN")
    ap.add_argument("--start", type=int, required=True, help="Start block (inclusive)")
    ap.add_argument("--end", type=int, default=None, help="End block (inclusive); default latest")
    ap.add_argument("--chunk", type=int, default=int(os.getenv("BLOCK_CHUNK", "1000")), help="Blocks per outer processing chunk")
    ap.add_argument("--block-batch", type=int, default=int(os.getenv("BLOCK_BATCH", "200")), help="How many blocks per JSON-RPC batch request")
    ap.add_argument("--timeout", type=int, default=int(os.getenv("RPC_TIMEOUT", "60")))
    ap.add_argument("--yaml", default=None, help="Optional: stablecoins YAML to ADD more event signatures (NO filtering)")
    args = ap.parse_args()

    if not args.rpc:
        raise SystemExit("Missing --rpc or ETH_RPC_URL")
    if not args.pg:
        raise SystemExit("Missing --pg or PG_DSN")

    rpc = RpcClient(args.rpc, timeout=args.timeout)

    latest = rpc.eth_block_number()
    end = args.end if args.end is not None else latest
    if args.start > end:
        raise SystemExit(f"--start {args.start} > --end {end}")

    sigs = list(DEFAULT_SPECIAL_SIGS)
    for s in load_sigs_from_yaml(args.yaml):
        if s not in sigs:
            sigs.append(s)

    topic0_to_sig: Dict[str, str] = {topic0(sig).lower(): sig for sig in sigs}

    with psycopg.connect(args.pg) as conn:
        ensure_schema(conn)

        for chunk_start in range(args.start, end + 1, args.chunk):
            chunk_end = min(chunk_start + args.chunk - 1, end)
            print(f"Processing blocks {chunk_start} - {chunk_end}")

            block_nums = list(range(chunk_start, chunk_end + 1))

            # 1) Blocks with full txs: needed for block timestamp, tx value, tx input/method_id
            blocks = fetch_blocks_adaptive(
                rpc,
                block_nums,
                full_tx=True,
                start_batch=args.block_batch,
            )

            # 2) Block receipts: needed for success, gas_used, effective_gas_price, and all logs
            receipts_batch = fetch_block_receipts_adaptive(
                rpc,
                block_nums,
                start_batch=args.block_batch,
            )

            receipts_by_block: Dict[int, List[dict]] = {
                bn: (receipts_batch[i] or []) for i, bn in enumerate(block_nums)
            }

            # 3) Insert blocks + txs
            insert_blocks_and_txs(conn, blocks, receipts_by_block)

            # 4) Extract logs from receipts
            transfer_logs, special_rows = extract_logs_from_receipts(
                receipts_by_block,
                TRANSFER_TOPIC0,
                topic0_to_sig,
            )

            # 5) Insert transfers
            insert_transfer_logs(conn, transfer_logs)

            # 6) Insert special token events
            insert_token_events(conn, special_rows)

    print("Done.")


if __name__ == "__main__":
    main()