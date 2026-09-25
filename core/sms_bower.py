# -*- coding: utf-8 -*-
"""同步 SMSBower 客户端，供现有 Codex 接码 provider 适配层使用。"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


class SmsBowerError(RuntimeError):
    pass


class SmsBowerNoNumbers(SmsBowerError):
    pass


class SmsBowerNoBalance(SmsBowerError):
    pass


class SmsBowerBudgetExceeded(SmsBowerError):
    def __init__(self, message: str, *, scope: str = "batch"):
        super().__init__(message)
        self.scope = scope


@dataclass(frozen=True)
class PriceOffer:
    country_id: str
    provider_id: str
    price: float
    count: int


def _as_float(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _as_int(value: Any) -> int:
    try:
        return max(0, int(float(value)))
    except (TypeError, ValueError):
        return 0


def _phone_digits(value: Any, *, country_id: str = "", country_code: str = "") -> str:
    """Normalize SMSBower's local/international variants to E.164 digits."""
    raw = str(value or "").strip()
    digits = "".join(ch for ch in raw if ch.isdigit())
    if not digits:
        raise SmsBowerError("SMSBower 返回空手机号")

    code_text = str(country_code or "").strip()
    code_upper = code_text.upper()
    country_id = str(country_id or "").strip()
    explicit_international = raw.startswith("+")
    if (
        not explicit_international
        and len(digits) == 10
        and (
            country_id in {"12", "36"}
            or code_upper in {"US", "USA", "CA", "CAN", "+1", "1"}
        )
    ):
        digits = "1" + digits
    elif not explicit_international and code_text.startswith("+"):
        dial_code = "".join(ch for ch in code_text if ch.isdigit())
        if dial_code and not digits.startswith(dial_code):
            digits = dial_code + digits.lstrip("0")

    if not 8 <= len(digits) <= 15:
        raise SmsBowerError(f"SMSBower 手机号长度不符合 E.164：digits={len(digits)}")
    return digits


def parse_price_offers(
    payload: Any, *, service: str = "dr", country: str = "",
    min_stock: int = 1, min_price: float | str | None = None,
    max_price: float | str | None = None,
) -> list[PriceOffer]:
    root = payload
    for _ in range(2):
        if isinstance(root, dict) and isinstance(root.get("data"), dict):
            root = root["data"]
        else:
            break
    if not isinstance(root, dict):
        return []
    service = str(service or "dr")
    country = str(country or "")
    floor = _as_float(min_price) if min_price not in (None, "") else None
    cap = _as_float(max_price) if max_price not in (None, "") else None
    tables: list[tuple[str, Any]] = []
    if country:
        if isinstance(root.get(country), dict):
            tables.append((country, root[country]))
        elif isinstance(root.get(service), (dict, list)):
            tables.append((country, root))
    else:
        tables = [(str(key), value) for key, value in root.items() if isinstance(value, (dict, list))]

    offers: list[PriceOffer] = []
    for country_id, table in tables:
        provider_table = table.get(service) if isinstance(table, dict) and service in table else (table if country else None)
        items = list(provider_table.items()) if isinstance(provider_table, dict) else list(enumerate(provider_table)) if isinstance(provider_table, list) else []
        for fallback_id, raw in items:
            if not isinstance(raw, dict):
                continue
            price = _as_float(raw.get("price"))
            count = _as_int(raw.get("count"))
            if (
                price is None
                or count < max(1, int(min_stock or 1))
                or (floor is not None and price + 1e-9 < floor)
                or (cap is not None and price > cap + 1e-9)
            ):
                continue
            offers.append(PriceOffer(
                country_id=country_id,
                provider_id=str(raw.get("provider_id") or raw.get("providerId") or fallback_id),
                price=price,
                count=count,
            ))
    unique = {(o.country_id, o.provider_id, o.price): o for o in offers}
    return sorted(unique.values(), key=lambda o: (o.price, -o.count, o.country_id, o.provider_id))


class _Budget:
    def __init__(self, limit: float | str | None, *, spent: float | str | None = None):
        parsed = _as_float(limit) if limit not in (None, "") else None
        # Only an empty value means unlimited. Numeric zero is an explicit
        # budget that forbids any positive-cost activation.
        self.limit = parsed
        self.spent = _as_float(spent) or 0.0
        self.reserved = 0.0
        self.batch_revision = ""
        self.lock = threading.Lock()

    def reserve(self, amount: float) -> float:
        with self.lock:
            projected = self.spent + self.reserved + amount
            if self.limit is not None and projected > self.limit + 1e-9:
                raise SmsBowerBudgetExceeded(
                    f"短信预算不足：已用 {self.spent:.4f}，已预留 {self.reserved:.4f}，"
                    f"本次 {amount:.4f}，上限 {self.limit:.4f}"
                )
            self.reserved += amount
            return amount

    def settle(self, reserved: float, actual: float) -> None:
        with self.lock:
            remaining = max(0.0, self.reserved - reserved)
            if self.limit is not None and self.spent + remaining + actual > self.limit + 1e-9:
                raise SmsBowerBudgetExceeded(f"号码实际价格 {actual:.4f} 会超过短信预算 {self.limit:.4f}")
            self.reserved = remaining
            self.spent += actual

    def release(self, amount: float) -> None:
        with self.lock:
            self.reserved = max(0.0, self.reserved - amount)

    def snapshot(self) -> dict:
        with self.lock:
            return {"limit": self.limit, "spent": self.spent, "reserved": self.reserved}


_STATE_LOCK = threading.Lock()
_BUDGETS: dict[str, _Budget] = {}
_QUARANTINE: dict[str, set[tuple[str, str]]] = {}
_ACTIVATIONS: dict[str, dict] = {}


def _batch_key(options: dict) -> str:
    return str(options.get("batch_id") or options.get("job_id") or "default")


def _budget(options: dict) -> _Budget:
    key = _batch_key(options)
    batch = {}
    batch_id = str(options.get("batch_id") or "")
    if batch_id:
        try:
            from core import db
            batch = db.get_registration_batch(batch_id) or {}
        except Exception:
            logger.debug("恢复 SMSBower 批次预算失败", exc_info=True)
    revision = str(batch.get("merge_revision") or "")
    with _STATE_LOCK:
        budget = _BUDGETS.get(key)
        if budget is None or (revision and budget.batch_revision != revision):
            # Completed batches can be merged without rewriting old job snapshots.
            # Refresh the effective limit and spent counter once per merge.
            budget = _Budget(
                batch.get("sms_budget_limit") if revision else options.get("budget"),
                spent=batch.get("sms_budget_spent"),
            )
            budget.batch_revision = revision
            _BUDGETS[key] = budget
        return budget


def _sync_budget(options: dict, budget: _Budget) -> None:
    batch_id = str(options.get("batch_id") or "")
    if not batch_id:
        return
    try:
        from core import db
        state = budget.snapshot()
        db.update_batch_sms_budget(batch_id, spent=state["spent"], reserved=state["reserved"])
    except Exception:
        logger.debug("同步 SMSBower 批次预算失败", exc_info=True)


def _mark_budget_exhausted(options: dict, error: Exception) -> None:
    if getattr(error, "scope", "batch") != "batch":
        return
    batch_id = str(options.get("batch_id") or "")
    if not batch_id:
        return
    try:
        from core import db
        db.mark_batch_sms_budget_exhausted(batch_id, str(error))
    except Exception:
        logger.debug("标记 SMSBower 批次预算耗尽失败", exc_info=True)


def _error_from_text(text: str) -> SmsBowerError | None:
    value = str(text or "").strip()
    upper = value.upper()
    if upper == "NO_BALANCE":
        return SmsBowerNoBalance("SMSBower 余额不足（NO_BALANCE）")
    if upper in {"NO_NUMBERS", "NO_NUMBERS_FOR_MAX_PRICE"} or "NO_NUMBERS" in upper:
        return SmsBowerNoNumbers(f"SMSBower 暂无符合价格的号码（{value}）")
    if upper == "BAD_KEY":
        return SmsBowerError("SMSBower API key 无效（BAD_KEY）")
    if upper in {"BAD_ACTION", "BAD_SERVICE", "BAD_COUNTRY", "BAD_STATUS", "NO_ACTIVATION"}:
        return SmsBowerError(f"SMSBower 请求错误：{value}")
    if upper.startswith("EARLY_CANCEL_DENIED"):
        return SmsBowerError(value)
    return None


def _call(http, options: dict, params: dict) -> tuple[str, Any]:
    url = str(options.get("handler_url") or "https://smsbower.page/stubs/handler_api.php")
    api_key = str(options.get("api_key") or "").strip()
    if not api_key:
        raise SmsBowerError("缺少 SMSBower API key")
    try:
        resp = http.get(url, params={"api_key": api_key, **params})
    except Exception as exc:
        raise SmsBowerError(f"SMSBower 请求失败: {exc}") from exc
    text = str(resp.text or "").strip()
    if resp.status_code != 200:
        raise SmsBowerError(f"SMSBower HTTP {resp.status_code}: {text[:200]}")
    parsed_error = _error_from_text(text)
    if parsed_error is not None:
        raise parsed_error
    try:
        data = resp.json()
    except Exception:
        data = None
    if isinstance(data, dict):
        raw_error = str(data.get("error") or data.get("message") or "").strip()
        parsed_error = _error_from_text(raw_error)
        if parsed_error is not None:
            raise parsed_error
        if data.get("error") or data.get("status") == "error":
            raise SmsBowerError(f"SMSBower API 错误：{raw_error or text[:200]}")
    return text, data


def acquire_number(http, options: dict) -> tuple[str, str, dict]:
    service = str(options.get("service") or "dr")
    country = str(options.get("country") or "")
    params = {"action": "getPricesV3", "service": service}
    if country:
        params["country"] = country
    _, prices = _call(http, options, params)
    offers = parse_price_offers(
        prices,
        service=service,
        country=country,
        min_price=options.get("min_price"),
        max_price=options.get("max_price"),
    )
    key = _batch_key(options)
    with _STATE_LOCK:
        blocked = set(_QUARANTINE.setdefault(key, set()))
    offers = [o for o in offers if (o.country_id, o.provider_id) not in blocked]
    if not offers:
        raise SmsBowerNoNumbers("SMSBower 没有符合价格和库存条件的号码")

    budget = _budget(options)
    errors: list[str] = []
    for offer in offers[:20]:
        try:
            reservation = budget.reserve(offer.price)
        except SmsBowerBudgetExceeded as exc:
            _sync_budget(options, budget)
            _mark_budget_exhausted(options, exc)
            raise
        _sync_budget(options, budget)
        activation_id = ""
        try:
            number_params = {
                "action": "getNumberV2", "service": service, "country": offer.country_id,
                "maxPrice": f"{offer.price:.8f}".rstrip("0").rstrip("."),
            }
            if offer.provider_id:
                number_params["providerIds"] = offer.provider_id
            text, data = _call(http, options, number_params)
            if isinstance(data, dict):
                activation_id = str(data.get("activationId") or data.get("id") or "")
                phone = str(data.get("phoneNumber") or data.get("phone") or "")
                parsed_actual = _as_float(data.get("activationCost"))
                actual = offer.price if parsed_actual is None else parsed_actual
                country_code = str(data.get("countryCode") or "")
            else:
                parts = text.split(":")
                activation_id, phone = (parts[1], parts[2]) if len(parts) >= 3 and text.startswith("ACCESS_NUMBER:") else ("", "")
                actual, country_code = offer.price, ""
            digits = _phone_digits(
                phone,
                country_id=offer.country_id,
                country_code=country_code,
            )
            if not activation_id or not 8 <= len(digits) <= 15:
                raise SmsBowerError(f"SMSBower getNumberV2 响应异常：{text[:160]}")
            cap = _as_float(options.get("max_price")) if options.get("max_price") not in (None, "") else None
            if cap is not None and actual > cap + 1e-9:
                raise SmsBowerBudgetExceeded(
                    f"号码实际价格 {actual:.4f} 超过单号上限 {cap:.4f}",
                    scope="price",
                )
            budget.settle(reservation, actual)
            metadata = {
                "sms_country": offer.country_id,
                "sms_provider_id": offer.provider_id,
                "sms_cost": actual,
                "batch_id": options.get("batch_id"),
            }
            with _STATE_LOCK:
                _ACTIVATIONS[activation_id] = metadata
            _sync_budget(options, budget)
            return activation_id, digits, metadata
        except (SmsBowerNoBalance, SmsBowerBudgetExceeded) as exc:
            budget.release(reservation)
            _sync_budget(options, budget)
            if isinstance(exc, SmsBowerBudgetExceeded):
                _mark_budget_exhausted(options, exc)
            if activation_id:
                try:
                    call_status(http, options, activation_id, 8)
                except Exception:
                    logger.warning("SMSBower 超限号码取消失败 id=%s", activation_id, exc_info=True)
            raise
        except SmsBowerError as exc:
            budget.release(reservation)
            _sync_budget(options, budget)
            if activation_id:
                try:
                    call_status(http, options, activation_id, 8)
                except Exception:
                    logger.warning("SMSBower 失败号码取消失败 id=%s", activation_id, exc_info=True)
            errors.append(str(exc))
    raise SmsBowerNoNumbers(errors[-1] if errors else "SMSBower 取号失败")


def call_status(http, options: dict, activation_id: str, status: int) -> str:
    text, _ = _call(http, options, {"action": "setStatus", "id": activation_id, "status": int(status)})
    return text


def get_status(http, options: dict, activation_id: str) -> str:
    text, _ = _call(http, options, {"action": "getStatus", "id": activation_id})
    return text


def reject_offer(activation_id: str, options: dict) -> None:
    with _STATE_LOCK:
        meta = _ACTIVATIONS.get(str(activation_id)) or {}
        key = _batch_key(options)
        _QUARANTINE.setdefault(key, set()).add((str(meta.get("sms_country") or ""), str(meta.get("sms_provider_id") or "")))


def activation_metadata(activation_id: str) -> dict:
    with _STATE_LOCK:
        return dict(_ACTIVATIONS.get(str(activation_id)) or {})


def forget_activation(activation_id: str) -> None:
    with _STATE_LOCK:
        _ACTIVATIONS.pop(str(activation_id), None)
