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
    instance: "ServiceContainer | None" = None
    db_manager: DatabaseManager | None = None
    vex_service: VEXService | None = None
    tix_service: TIXService | None = None
    package_service: PackageService | None = None
    version_service: VersionService | None = None
    vulnerability_service: VulnerabilityService | None = None
    json_encoder: JSONEncoder | None = None
    jwt_bearer: JWTBearer | None = None

    def __new__(cls) -> "ServiceContainer":
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance

    def get_db(self) -> DatabaseManager:
        if self.db_manager is None:
            self.db_manager = get_database_manager()
        return self.db_manager

    def get_vex_service(self) -> VEXService:
        if self.vex_service is None:
            self.vex_service = VEXService(self.get_db())
        return self.vex_service

    def get_tix_service(self) -> TIXService:
        if self.tix_service is None:
            self.tix_service = TIXService(self.get_db())
        return self.tix_service

    def get_package_service(self) -> PackageService:
        if self.package_service is None:
            self.package_service = PackageService(self.get_db())
        return self.package_service

    def get_version_service(self) -> VersionService:
        if self.version_service is None:
            self.version_service = VersionService(self.get_db())
        return self.version_service

    def get_vulnerability_service(self) -> VulnerabilityService:
        if self.vulnerability_service is None:
            self.vulnerability_service = VulnerabilityService(self.get_db())
        return self.vulnerability_service

    def get_json_encoder(self) -> JSONEncoder:
        if self.json_encoder is None:
            self.json_encoder = JSONEncoder()
        return self.json_encoder

    def get_jwt_bearer(self) -> JWTBearer:
        if self.jwt_bearer is None:
            self.jwt_bearer = JWTBearer()
        return self.jwt_bearer


container: ServiceContainer | None = None


def get_service_container() -> ServiceContainer:
    global container
    if container is None:
        container = ServiceContainer()
    return container


def get_db() -> DatabaseManager:
    return get_service_container().get_db()


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
