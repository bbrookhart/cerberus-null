"""Mission, identity, policy-health, and independent emergency-stop state."""

from __future__ import annotations

import json
from pathlib import Path

from cerberus_null.models import Identity, IdentityKind, Mission


class IdentityResolver:
    def __init__(self, identities: tuple[Identity, ...]) -> None:
        self._identities = {identity.identity_id: identity for identity in identities}

    def resolve(self, identity_id: str, kind: IdentityKind) -> Identity | None:
        identity = self._identities.get(identity_id)
        if identity is None or identity.kind is not kind or not identity.active:
            return None
        return identity


class MissionRegistry:
    def __init__(self, missions: tuple[Mission, ...]) -> None:
        self._missions = {mission.mission_id: mission for mission in missions}

    def get(self, mission_id: str) -> Mission | None:
        return self._missions.get(mission_id)

    def list(self) -> tuple[Mission, ...]:
        return tuple(self._missions.values())


class PolicyHealth:
    def __init__(self) -> None:
        self.healthy = True


class EmergencyStop:
    """Independent human-controlled revocation state outside the agent boundary."""

    def __init__(
        self,
        state_file: Path | None = None,
        *,
        authorized_controllers: frozenset[str] = frozenset({"human-operator-01"}),
    ) -> None:
        self._state_file = state_file
        self._authorized_controllers = authorized_controllers
        self._engaged = False
        if state_file and state_file.exists():
            self._engaged = bool(json.loads(state_file.read_text()).get("engaged", False))

    @property
    def engaged(self) -> bool:
        return self._engaged

    def engage(self, actor: Identity) -> None:
        if (
            actor.kind is not IdentityKind.HUMAN
            or not actor.active
            or actor.identity_id not in self._authorized_controllers
        ):
            raise PermissionError("only an active human operator may engage emergency stop")
        self._engaged = True
        self._persist()

    def release(self, actor: Identity) -> None:
        if (
            actor.kind is not IdentityKind.HUMAN
            or not actor.active
            or actor.identity_id not in self._authorized_controllers
        ):
            raise PermissionError("only an active human operator may release emergency stop")
        self._engaged = False
        self._persist()

    def _persist(self) -> None:
        if self._state_file is None:
            return
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        self._state_file.write_text(json.dumps({"engaged": self._engaged}, indent=2) + "\n")
