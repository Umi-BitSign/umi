"""Share one authenticated adoption frontier among a service's native consumers."""

from .competition_reward_adoption import verify_adoption_selection
from .competition_reward_adoption_feed import RewardAdoptionFeed
from .protocol import canonical_json_bytes


def open_reward_adoption_feed(root, *, source, series, policy, initial, deferred=False):
    if source is None:
        return None
    feed = RewardAdoptionFeed(
        root, source=source, series=series, policy=policy, initial=initial, deferred=deferred
    )
    if not deferred:
        feed.refresh()
    return feed


class RewardAdoptionConsumer:
    """Getters use the accepted immutable snapshot; refresh is an explicit operation."""

    def _configure_reward_adoptions(self, selection, *, series, policy, feed=None):
        self._reward_adoption_feed = feed
        if feed is None:
            self._reward_adoptions = verify_adoption_selection(selection, series, policy)
            return
        if type(feed) is not RewardAdoptionFeed or feed.series != series or feed.policy != policy:
            raise ValueError("reward adoption feed differs from consumer authority")
        selected = feed.selected
        if selection is not None:
            available = (
                set()
                if selected is None
                else {canonical_json_bytes(item) for item in selected.adoptions}
            )
            if (
                selected is None
                or selected.maximum_decisions < selection.maximum_decisions
                or any(canonical_json_bytes(item) not in available for item in selection.adoptions)
            ):
                raise ValueError("reward adoption feed omits the consumer's selected lineage")
        self._reward_adoptions = None

    @property
    def reward_adoptions(self):
        feed = self._reward_adoption_feed
        return self._reward_adoptions if feed is None else feed.selected

    @reward_adoptions.setter
    def reward_adoptions(self, selection):
        if self._reward_adoption_feed is not None:
            raise ValueError("signed reward feed selection changes only through its owner")
        self._reward_adoptions = selection

    def refresh_reward_adoptions(self):
        feed = self._reward_adoption_feed
        return self._reward_adoptions if feed is None else feed.refresh()
