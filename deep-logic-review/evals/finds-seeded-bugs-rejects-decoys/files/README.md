# Shop service
Small order service. `shop/api.py` is the entry point; handlers receive the authenticated `user`.

Business rules live in `docs/rules.md`. Orders belong to one customer; only the owner or a user with role `admin` may read or change an order.
