"""
Install:
  pip install psycopg[binary] requests python-dotenv

Env:
  ETH_RPC_URL
  PG_DSN
  SELECT_BATCH   default 50000   # how many DB rows fetched per outer loop
  RPC_BATCH      default 1000    # how many eth_getCode calls per JSON-RPC batch
  RPC_TIMEOUT    default 60

Usage:
  python address_classifier.py
  python address_classifier.py --start-id 123456789
  python address_classifier.py --select-batch 20000 --rpc-batch 500
"""

import os
import time
import argparse
from typing import Any, List, Tuple, Optional

import requests
import psycopg
from dotenv import load_dotenv

load_dotenv()


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
                wait_s = min(2 ** (attempt - 1), 20)
                print(f"[RPC] attempt {attempt}/{self.max_retries} failed: {e}; retrying in {wait_s}s")
                time.sleep(wait_s)
        raise RuntimeError(f"RPC request failed after retries: {last}") from last

    def batch(self, calls: List[Tuple[str, list]]) -> List[Any]:
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

    def eth_get_code_batch(self, addresses: List[str], block_tag: str = "latest") -> List[str]:
        calls = [("eth_getCode", [addr, block_tag]) for addr in addresses]
        return self.batch(calls)


def bytea_to_hex_addr(value: Any) -> str:
    if isinstance(value, memoryview):
        raw = bytes(value)
    elif isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        raise TypeError(f"Unsupported addr type: {type(value)}")

    return "0x" + raw.hex()


def chunked(seq: List[Any], size: int):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def ensure_schema(conn: psycopg.Connection) -> None:
    with conn.cursor() as cur:
        cur.execute("""
            ALTER TABLE address
            ADD COLUMN IF NOT EXISTS is_contract BOOLEAN
        """)
    conn.commit()


def create_temp_update_table(conn: psycopg.Connection) -> None:
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TEMP TABLE IF NOT EXISTS tmp_address_classification (
                id BIGINT PRIMARY KEY,
                is_contract BOOLEAN NOT NULL
            ) ON COMMIT PRESERVE ROWS
        """)
    conn.commit()


def fetch_address_batch(
    conn: psycopg.Connection,
    start_id: Optional[int],
    end_id: Optional[int],
    select_batch: int,
    only_null: bool,
) -> List[Tuple[int, Any]]:
    with conn.cursor() as cur:
        if start_id is None and end_id is None:
            if only_null:
                cur.execute("""
                    SELECT id, addr
                    FROM address
                    WHERE is_contract IS NULL
                    ORDER BY id
                    LIMIT %s
                """, (select_batch,))
            else:
                cur.execute("""
                    SELECT id, addr
                    FROM address
                    ORDER BY id
                    LIMIT %s
                """, (select_batch,))
        elif start_id is None and end_id is not None:
            if only_null:
                cur.execute("""
                    SELECT id, addr
                    FROM address
                    WHERE id <= %s
                      AND is_contract IS NULL
                    ORDER BY id
                    LIMIT %s
                """, (end_id, select_batch))
            else:
                cur.execute("""
                    SELECT id, addr
                    FROM address
                    WHERE id <= %s
                    ORDER BY id
                    LIMIT %s
                """, (end_id, select_batch))
        elif start_id is not None and end_id is None:
            if only_null:
                cur.execute("""
                    SELECT id, addr
                    FROM address
                    WHERE id > %s
                      AND is_contract IS NULL
                    ORDER BY id
                    LIMIT %s
                """, (start_id, select_batch))
            else:
                cur.execute("""
                    SELECT id, addr
                    FROM address
                    WHERE id > %s
                    ORDER BY id
                    LIMIT %s
                """, (start_id, select_batch))
        else:
            if only_null:
                cur.execute("""
                    SELECT id, addr
                    FROM address
                    WHERE id > %s
                      AND id <= %s
                      AND is_contract IS NULL
                    ORDER BY id
                    LIMIT %s
                """, (start_id, end_id, select_batch))
            else:
                cur.execute("""
                    SELECT id, addr
                    FROM address
                    WHERE id > %s
                      AND id <= %s
                    ORDER BY id
                    LIMIT %s
                """, (start_id, end_id, select_batch))

        return cur.fetchall()


def bulk_update_classification(conn: psycopg.Connection, updates: List[Tuple[int, bool]]) -> None:
    with conn.cursor() as cur:
        cur.execute("TRUNCATE tmp_address_classification")
        cur.executemany(
            "INSERT INTO tmp_address_classification (id, is_contract) VALUES (%s, %s)",
            updates
        )
        cur.execute("""
            UPDATE address AS a
            SET is_contract = t.is_contract
            FROM tmp_address_classification AS t
            WHERE a.id = t.id
        """)
    conn.commit()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--start-id", type=int, default=None)
    parser.add_argument("--end-id", type=int, default=None)
    parser.add_argument("--select-batch", type=int, default=int(os.getenv("SELECT_BATCH", "50000")))
    parser.add_argument("--rpc-batch", type=int, default=int(os.getenv("RPC_BATCH", "1000")))
    parser.add_argument("--rpc-timeout", type=int, default=int(os.getenv("RPC_TIMEOUT", "60")))
    parser.add_argument(
        "--only-null",
        action="store_true",
        help="Only process rows where is_contract IS NULL"
    )
    args = parser.parse_args()

    rpc_url = os.getenv("ETH_RPC_URL")
    pg_dsn = os.getenv("PG_DSN")

    if not rpc_url:
        raise RuntimeError("Missing ETH_RPC_URL in environment")
    if not pg_dsn:
        raise RuntimeError("Missing PG_DSN in environment")

    rpc = RpcClient(url=rpc_url, timeout=args.rpc_timeout)

    print("[INIT] Connecting to Postgres...")
    with psycopg.connect(pg_dsn) as conn:
        ensure_schema(conn)
        create_temp_update_table(conn)

        last_seen_id = args.start_id
        total_processed = 0
        total_eoa = 0
        total_contract = 0
        t0 = time.time()

        print(
            f"[INIT] start_id={args.start_id} end_id={args.end_id} "
            f"select_batch={args.select_batch} rpc_batch={args.rpc_batch} "
            f"only_null={args.only_null}"
        )

        while True:
            rows = fetch_address_batch(
                conn=conn,
                start_id=last_seen_id,
                end_id=args.end_id,
                select_batch=args.select_batch,
                only_null=args.only_null,
            )

            if not rows:
                break

            batch_start = time.time()
            updates: List[Tuple[int, bool]] = []

            for sub in chunked(rows, args.rpc_batch):
                ids = [row[0] for row in sub]
                addrs = [bytea_to_hex_addr(row[1]) for row in sub]
                codes = rpc.eth_get_code_batch(addrs, block_tag="latest")

                for row_id, code in zip(ids, codes):
                    updates.append((row_id, code != "0x"))

            bulk_update_classification(conn, updates)

            batch_processed = len(updates)
            batch_contract = sum(1 for _, is_contract in updates if is_contract)
            batch_eoa = batch_processed - batch_contract

            total_processed += batch_processed
            total_contract += batch_contract
            total_eoa += batch_eoa
            last_seen_id = rows[-1][0]

            elapsed = time.time() - batch_start
            total_elapsed = time.time() - t0
            rate = batch_processed / elapsed if elapsed > 0 else 0.0

            print(
                f"[BATCH] last_id={last_seen_id} rows={batch_processed} "
                f"eoa={batch_eoa} contract={batch_contract} "
                f"batch_time={elapsed:.2f}s rate={rate:.1f} rows/s "
                f"total={total_processed} total_time={total_elapsed/60:.1f}m"
            )

        total_elapsed = time.time() - t0
        print(
            f"[DONE] processed={total_processed} eoa={total_eoa} "
            f"contract={total_contract} time={total_elapsed/60:.2f}m"
        )


if __name__ == "__main__":
    main()