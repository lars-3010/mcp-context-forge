# Standard
from typing import List


# Fast-track versioning configuration
class VersioningConfig:
    # 0.6.0 settings
    enable_legacy_support: bool = True  # Still serve legacy in 0.6.0
    enable_deprecation_headers: bool = True  # Loud warnings
    legacy_removal_version: str = "0.7.0"  # Hard deadline

    # 0.7.0 settings
    legacy_support_removed: bool = True  # No more legacy paths

    # Experimental access
    experimental_access_roles: List[str] = ["platform_admin", "developer"]
