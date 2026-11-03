"""Stock reservation and price cache, used by the async checkout worker."""
import asyncio

_prices = {}
_price_cache = {}


async def _audit_log(sku, qty):
    await asyncio.sleep(0)


async def reserve(stock, sku, qty):
    available = stock.get(sku, 0)
    if available < qty:
        return False
    await _audit_log(sku, qty)
    stock[sku] = available - qty
    return True


def set_price(sku, cents):
    _prices[sku] = cents


def get_price(sku):
    if sku not in _price_cache:
        _price_cache[sku] = _prices[sku]
    return _price_cache[sku]
