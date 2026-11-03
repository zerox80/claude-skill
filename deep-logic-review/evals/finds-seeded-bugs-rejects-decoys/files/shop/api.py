"""HTTP-style handlers. `user` is authenticated by the gateway: {"name": str, "role": str}."""
from . import metrics, pricing
from .store import Store

store = Store()


class Forbidden(Exception):
    pass


def validate_lines(lines):
    if not lines:
        raise ValueError("order is empty")
    for line in lines:
        if line["qty"] <= 0 or line["unit"] < 0:
            raise ValueError("bad line")


def create_order(user, lines):
    validate_lines(lines)
    net = sum(pricing.line_total(l["unit"], l["qty"]) for l in lines)
    total = net + pricing.tax(net)
    order_id = store.create_order(user["name"], total, lines)
    metrics.emit("order_created", pricing.average_line(lines))
    return order_id


def get_order(user, order_id):
    order = store.get_order(order_id)
    if order is None:
        raise KeyError(order_id)
    return order


def cancel_order(user, order_id):
    order = store.get_order(order_id)
    if order is None:
        raise KeyError(order_id)
    if order["owner"] != user["name"] and user["role"] != "admin":
        raise Forbidden()
    return {"cancelled": order_id}
