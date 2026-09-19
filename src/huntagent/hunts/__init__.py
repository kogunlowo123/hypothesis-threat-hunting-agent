"""The hunt library."""

from __future__ import annotations

from huntagent.hunts.base import Hunt, HuntContext
from huntagent.hunts.cloud import CloudAbuseHunt
from huntagent.hunts.endpoint import PersistenceHunt, ProcessChainHunt, RareProcessHunt
from huntagent.hunts.identity import ImpossibleTravelHunt, LateralFanOutHunt, PasswordAttackHunt
from huntagent.hunts.network import BeaconingHunt, DgaHunt, DnsTunnelHunt, ExfiltrationHunt

ALL_HUNTS: tuple[Hunt, ...] = (
    BeaconingHunt(),
    DnsTunnelHunt(),
    DgaHunt(),
    ExfiltrationHunt(),
    PasswordAttackHunt(),
    ImpossibleTravelHunt(),
    LateralFanOutHunt(),
    ProcessChainHunt(),
    PersistenceHunt(),
    RareProcessHunt(),
    CloudAbuseHunt(),
)


def hunt_by_id(hunt_id: str) -> Hunt | None:
    """Look up a hunt by its identifier."""
    return next((h for h in ALL_HUNTS if h.id == hunt_id), None)


__all__ = ["ALL_HUNTS", "Hunt", "HuntContext", "hunt_by_id"]
