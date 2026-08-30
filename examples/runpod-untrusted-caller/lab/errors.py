"""Stable errors for the non-networked adversarial lab."""

from __future__ import annotations


class LabError(RuntimeError):
    """Base class for a fail-closed lab operation."""


class LabProtocolError(LabError):
    """A strict wire message was malformed, noncanonical, or incomplete."""


class LabBindingError(LabError):
    """A worker key, digest, request, credential, or receipt binding failed."""


class DuplicateRunIdError(LabError):
    """A case or worker request reused a locally reserved identifier."""


class LabTimeoutError(LabError):
    """The fake or live worker failed to return within the local deadline."""


class ExperimentRecordError(LabError):
    """A locally signed experiment record failed JWS or schema verification."""
