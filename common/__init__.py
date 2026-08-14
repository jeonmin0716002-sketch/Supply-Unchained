"""Code shared by more than one detection part.

Only things genuinely needed by two or more of api/, engine/ and scoring/
belong here. Part-specific logic stays in its own directory -- this is not a
utils dumping ground.
"""

from common.pypi import (
    ArchiveError,
    Artifact,
    PackageContext,
    PackageNotFound,
    ProjectData,
    PyPIError,
    new_client,
)

__all__ = [
    "ArchiveError",
    "Artifact",
    "PackageContext",
    "PackageNotFound",
    "ProjectData",
    "PyPIError",
    "new_client",
]
