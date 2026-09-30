"""Retryable chain timing for a new weight submission."""


class WeightRateLimitWait(ValueError):
    reason_code = "weights_rate_limited"

    def __init__(self, observed_block: int, next_eligible_block: int):
        self.observed_block = observed_block
        self.next_eligible_block = next_eligible_block
        super().__init__("successor validator weight rate limit has not elapsed")


def require_weight_interval(observation) -> None:
    next_block = observation.validator_last_update + observation.weights_rate_limit
    if next_block > observation.block:
        raise WeightRateLimitWait(observation.block, next_block)
