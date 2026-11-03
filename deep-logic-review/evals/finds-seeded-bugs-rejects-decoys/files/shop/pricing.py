"""Pricing rules. See docs/rules.md."""

BULK_THRESHOLD = 10
TAX_BPS = 1900


def line_total(unit_cents, qty):
    total = unit_cents * qty
    if qty > BULK_THRESHOLD:
        total = total * 90 // 100
    return total


def tax(net_cents):
    # Rounded down on purpose, see FIN-12 in docs/rules.md.
    return net_cents * TAX_BPS // 10000


def average_line(lines):
    # Callers go through api.validate_lines, which rejects empty orders.
    return sum(line_total(l["unit"], l["qty"]) for l in lines) / len(lines)
