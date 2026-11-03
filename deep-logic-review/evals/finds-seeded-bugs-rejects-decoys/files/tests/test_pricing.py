from shop import pricing


def test_no_discount_for_small_orders():
    assert pricing.line_total(100, 2) == 200


def test_discount_for_large_orders():
    assert pricing.line_total(100, 20) == 1800


def test_tax_rounds_down():
    assert pricing.tax(199) == 37
