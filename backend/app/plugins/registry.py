from app.plugins.base import BasePlugin
from app.plugins.basic_sqli import BasicSqliPlugin
from app.plugins.cookie_flags import CookieFlagsPlugin
from app.plugins.exposed_files import ExposedFilesPlugin
from app.plugins.reflected_xss import ReflectedXssPlugin
from app.plugins.security_headers import SecurityHeadersPlugin
from app.plugins.technology import TechnologyPlugin

PLUGINS: dict[str, BasePlugin] = {plugin.name: plugin for plugin in (
    SecurityHeadersPlugin(), CookieFlagsPlugin(), ExposedFilesPlugin(),
    TechnologyPlugin(), ReflectedXssPlugin(), BasicSqliPlugin(),
)}


def selected_plugins(names: list[str] | None) -> list[BasePlugin]:
    if not names:
        return list(PLUGINS.values())
    unknown = set(names) - PLUGINS.keys()
    if unknown:
        raise ValueError(f"Unknown plugins: {', '.join(sorted(unknown))}")
    return [PLUGINS[name] for name in names]
