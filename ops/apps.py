from django.apps import AppConfig


class OpsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "ops"

    def ready(self) -> None:
        from . import audit  # noqa: F401 - connects login/logout audit signals
