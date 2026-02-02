"""Module registry for reconnaissance modules."""

from .base import BaseModule
from .subdomain import SubdomainModule
from .portscan import PortScanModule
from .techdetect import TechDetectModule
from .directory import DirectoryModule
from .wayback import WaybackModule
from .probe import ProbeModule

# Module registry - maps module names to their classes
MODULE_REGISTRY: dict[str, type[BaseModule]] = {
    "subdomain": SubdomainModule,
    "probe": ProbeModule,
    "portscan": PortScanModule,
    "techdetect": TechDetectModule,
    "directory": DirectoryModule,
    "wayback": WaybackModule,
}


def get_all_modules(config: dict) -> list[BaseModule]:
    """Get instances of all registered modules.

    Args:
        config: Global configuration dictionary.

    Returns:
        List of module instances.
    """
    return [module_class(config) for module_class in MODULE_REGISTRY.values()]


def get_module(name: str, config: dict) -> BaseModule | None:
    """Get a specific module instance by name.

    Args:
        name: Module name.
        config: Global configuration dictionary.

    Returns:
        Module instance or None if not found.
    """
    module_class = MODULE_REGISTRY.get(name)
    if module_class:
        return module_class(config)
    return None


def get_available_modules(config: dict) -> list[BaseModule]:
    """Get instances of all modules that have their required tools available.

    Args:
        config: Global configuration dictionary.

    Returns:
        List of available module instances.
    """
    modules = []
    for module in get_all_modules(config):
        if module.is_available():
            modules.append(module)
    return modules


def check_module_availability(config: dict) -> dict[str, dict]:
    """Check availability status of all modules.

    Args:
        config: Global configuration dictionary.

    Returns:
        Dictionary mapping module names to availability info.
    """
    status = {}
    for name, module_class in MODULE_REGISTRY.items():
        module = module_class(config)
        status[name] = {
            "available": module.is_available(),
            "description": module.description,
            "required_tools": module.required_tools,
            "missing_tools": module.get_missing_tools(),
        }
    return status


__all__ = [
    "BaseModule",
    "SubdomainModule",
    "ProbeModule",
    "PortScanModule",
    "TechDetectModule",
    "DirectoryModule",
    "WaybackModule",
    "MODULE_REGISTRY",
    "get_all_modules",
    "get_module",
    "get_available_modules",
    "check_module_availability",
]
