"""Refund handling."""


class RefundError(Exception):
    pass


def refund(order, amount_cents):
    if amount_cents <= 0:
        raise RefundError("amount must be positive")
    if amount_cents > order["paid_cents"]:
        raise RefundError("amount exceeds payment")
    order["refunded_cents"] = order.get("refunded_cents", 0) + amount_cents
    return order["refunded_cents"]
