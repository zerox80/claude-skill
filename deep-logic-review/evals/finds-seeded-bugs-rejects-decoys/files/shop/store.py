"""SQLite persistence. One shared connection per process."""
import sqlite3

ALLOWED_SORT = {"id", "created"}


class Store:
    def __init__(self, path=":memory:"):
        self.conn = sqlite3.connect(path)
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, owner TEXT NOT NULL,
                created INTEGER DEFAULT 0, total INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS items(order_id INTEGER NOT NULL, sku TEXT NOT NULL, qty INTEGER NOT NULL CHECK(qty > 0));
            """
        )

    def create_order(self, owner, total, items):
        cur = self.conn.execute("INSERT INTO orders(owner, total) VALUES (?, ?)", (owner, total))
        order_id = cur.lastrowid
        for item in items:
            self.conn.execute(
                "INSERT INTO items(order_id, sku, qty) VALUES (?, ?, ?)",
                (order_id, item["sku"], item["qty"]),
            )
        self.conn.commit()
        return order_id

    def get_order(self, order_id):
        row = self.conn.execute("SELECT id, owner, total FROM orders WHERE id = ?", (order_id,)).fetchone()
        return None if row is None else {"id": row[0], "owner": row[1], "total": row[2]}

    def list_orders(self, sort):
        if sort not in ALLOWED_SORT:
            raise ValueError("bad sort")
        return self.conn.execute(f"SELECT id, owner, total FROM orders ORDER BY {sort}").fetchall()
