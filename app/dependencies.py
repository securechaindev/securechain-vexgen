from app.database import DatabaseManager, get_database_manager
from app.services import (
    PackageService,
    TIXService,
    VersionService,
    VEXService,
    VulnerabilityService,
)
from app.utils import JSONEncoder, JWTBearer


class ServiceContainer:
    _instance: "ServiceContainer | None" = None
    _db_manager: DatabaseManager | None = None
    _vex_service: VEXService | None = None
    _tix_service: TIXService | None = None
    _package_service: PackageService | None = None
    _version_service: VersionService | None = None
    _vulnerability_service: VulnerabilityService | None = None
    _json_encoder: JSONEncoder | None = None
    _jwt_bearer: JWTBearer | None = None

    def __new__(cls) -> "ServiceContainer":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def _get_db(self) -> DatabaseManager:
        if self._db_manager is None:
            self._db_manager = get_database_manager()
        return self._db_manager

    def get_vex_service(self) -> VEXService:
        if self._vex_service is None:
            self._vex_service = VEXService(self._get_db())
        return self._vex_service

    def get_tix_service(self) -> TIXService:
        if self._tix_service is None:
            self._tix_service = TIXService(self._get_db())
        return self._tix_service

    def get_package_service(self) -> PackageService:
        if self._package_service is None:
            self._package_service = PackageService(self._get_db())
        return self._package_service

    def get_version_service(self) -> VersionService:
        if self._version_service is None:
            self._version_service = VersionService(self._get_db())
        return self._version_service

    def get_vulnerability_service(self) -> VulnerabilityService:
        if self._vulnerability_service is None:
            self._vulnerability_service = VulnerabilityService(self._get_db())
        return self._vulnerability_service

    def get_json_encoder(self) -> JSONEncoder:
        if self._json_encoder is None:
            self._json_encoder = JSONEncoder()
        return self._json_encoder

    def get_jwt_bearer(self) -> JWTBearer:
        if self._jwt_bearer is None:
            self._jwt_bearer = JWTBearer()
        return self._jwt_bearer


_container: ServiceContainer | None = None


def get_service_container() -> ServiceContainer:
    global _container
    if _container is None:
        _container = ServiceContainer()
    return _container


def get_db() -> DatabaseManager:
    return get_service_container()._get_db()


def get_vex_service() -> VEXService:
    return get_service_container().get_vex_service()


def get_tix_service() -> TIXService:
    return get_service_container().get_tix_service()


def get_package_service() -> PackageService:
    return get_service_container().get_package_service()


def get_version_service() -> VersionService:
    return get_service_container().get_version_service()


def get_vulnerability_service() -> VulnerabilityService:
    return get_service_container().get_vulnerability_service()


def get_json_encoder() -> JSONEncoder:
    return get_service_container().get_json_encoder()


def get_jwt_bearer() -> JWTBearer:
    return get_service_container().get_jwt_bearer()
