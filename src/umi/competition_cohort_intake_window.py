"""Sequential intake projection from authenticated native cohort states.

The owner feeds verified plans/states at startup and publication. Public polling
reads this bounded projection; admission refreshes the predecessor under its
existing native fence. A scheduled deadline or pending transition cannot open it.
"""

from threading import Lock

from .competition_cohort_recovery import PHASES
from .open_competition import digest


class SequentialIntakeWindow:
    def __init__(self, first_sequence, bindings):
        self.first_sequence = first_sequence
        self.bindings = bindings
        self._plans = {}
        self._states = {}
        self._lock = Lock()

    def observe(self, plan, state):
        cohort = digest(plan)
        if cohort != state.cohort_sha256 or self.bindings.get(cohort) != state.authority_sha256:
            raise ValueError("intake window differs from authenticated cohort binding")
        with self._lock:
            prior = self._states.get(cohort)
            if prior is not None and state.sequence < prior.sequence:
                return
            if (
                prior is not None
                and state.sequence == prior.sequence
                and state.tip_sha256 != prior.tip_sha256
            ):
                raise ValueError("intake window observed a conflicting native tip")
            self._plans[cohort] = plan
            self._states[cohort] = state

    def plan(self, cohort):
        with self._lock:
            return self._plans[cohort]

    def predecessor(self, cohort):
        with self._lock:
            plan = self._plans.get(cohort)
            if plan is None or self.first_sequence is None or plan.sequence < self.first_sequence:
                return None
            matches = [
                key
                for key, item in self._plans.items()
                if item.launch_sha256 == plan.launch_sha256 and item.sequence == plan.sequence - 1
            ]
            if len(matches) > 1:
                raise ValueError("ambiguous intake predecessor in selected launch")
            return matches[0] if matches else None

    def status(self, cohort):
        predecessor = self.predecessor(cohort)
        with self._lock:
            plan = self._plans.get(cohort)
            if self.first_sequence is None:
                return None
            if plan is not None and plan.sequence < self.first_sequence:
                return None
            previous = self._states.get(predecessor)
            ready_phases = set(PHASES[PHASES.index("requests") :]) | {"complete"}
            opened = previous is not None and previous.phase in ready_phases
            own = self._states.get(cohort)
            opened = opened and own is not None and own.phase == "intake"
            return {
                "stage": "accepting_new_submissions"
                if opened
                else "awaiting_predecessor_challenges",
                "new_admissions_open": opened,
                "accepted_uploads_may_finish": True,
                "predecessor_cohort_sha256": predecessor,
                "predecessor_phase": None if previous is None else previous.phase,
                "completed": int(opened),
                "total": 1,
                "percent": 100 if opened else 0,
                "eta_seconds": None,
                "eta_basis": "authenticated_predecessor_request_phase",
                "eta_scope": "new_admission_window_only",
                "stalled_or_retrying": False,
            }
