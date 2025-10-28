from __future__ import annotations

from app.apis.github_service import GitHubService
from app.database import DatabaseManager
from app.logger import LoggerManager
from app.services import (
    PackageService,
    TIXService,
    VersionService,
    VEXService,
    VulnerabilityService,
)
from app.utils import JSONEncoder, JWTBearer


class ServiceContainer:
    instance: ServiceContainer | None = None
    db_manager: DatabaseManager | None = None
    vex_service: VEXService | None = None
    tix_service: TIXService | None = None
    package_service: PackageService | None = None
    version_service: VersionService | None = None
    vulnerability_service: VulnerabilityService | None = None
    github_service: GitHubService | None = None
    json_encoder: JSONEncoder | None = None
    jwt_bearer: JWTBearer | None = None
    logger: LoggerManager | None = None

    def __new__(cls) -> ServiceContainer:
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance

    def get_db(self) -> DatabaseManager:
        if self.db_manager is None:
            self.db_manager = DatabaseManager()
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

    def get_github_service(self) -> GitHubService:
        if self.github_service is None:
            self.github_service = GitHubService()
        return self.github_service

    def get_json_encoder(self) -> JSONEncoder:
        if self.json_encoder is None:
            self.json_encoder = JSONEncoder()
        return self.json_encoder

    def get_jwt_bearer(self) -> JWTBearer:
        if self.jwt_bearer is None:
            self.jwt_bearer = JWTBearer()
        return self.jwt_bearer

    def get_logger(self) -> LoggerManager:
        if self.logger is None:
            self.logger = LoggerManager("logs/errors.log")
        return self.logger


def get_db() -> DatabaseManager:
    return ServiceContainer().get_db()


def get_vex_service() -> VEXService:
    return ServiceContainer().get_vex_service()


def get_tix_service() -> TIXService:
    return ServiceContainer().get_tix_service()


def get_package_service() -> PackageService:
    return ServiceContainer().get_package_service()


def get_version_service() -> VersionService:
    return ServiceContainer().get_version_service()


def get_vulnerability_service() -> VulnerabilityService:
    return ServiceContainer().get_vulnerability_service()


def get_github_service() -> GitHubService:
    return ServiceContainer().get_github_service()


def get_json_encoder() -> JSONEncoder:
    return ServiceContainer().get_json_encoder()


def get_jwt_bearer() -> JWTBearer:
    return ServiceContainer().get_jwt_bearer()


def get_logger() -> LoggerManager:
    return ServiceContainer().get_logger()
