"""
Main application orchestrator for the eduroam profile generator.
"""

from src.config import Config
from src.domain import (
    Realm,
    TestServer,
    ProfileConfig,
    EduroamError,
    RateLimitError,
    NetworkError,
)
from src.infrastructure import LocalFileRepository, SubprocessExecutor
from src.services import (
    CertificateService,
    AuthenticationService,
    ProfileService,
    LoggingService,
)


class EduroamProfileGenerator:
    """Main application class for generating eduroam profiles."""

    def __init__(self, config: Config = Config()):
        self.config = config

        # Initialize infrastructure
        self.file_repo = LocalFileRepository()
        self.executor = SubprocessExecutor()

        # Initialize services
        self.cert_service = CertificateService(
            file_repo=self.file_repo,
            command_executor=self.executor,
            cert_dir=config.CERT_DIR,
            temp_dir=config.TEMP_DIR,
        )

        self.auth_service = AuthenticationService(
            file_repo=self.file_repo,
            cert_service=self.cert_service,
            log_dir=config.LOG_DIR,
            account=config.TEST_ACCOUNT,
            password=config.TEST_PASSWORD,
        )

        self.profile_service = ProfileService(
            file_repo=self.file_repo,
            template_dir=config.TEMPLATE_DIR,
            profile_dir=config.PROFILE_DIR,
        )

        self.logging_service = LoggingService(
            file_repo=self.file_repo, log_dir=config.LOG_DIR
        )

    def initialize(self) -> None:
        """Initialize the application environment."""
        # Create necessary directories
        for directory in self.config.get_all_directories():
            self.file_repo.ensure_directory(directory)

        # Initialize logging
        self.logging_service.initialize()

    def run(self) -> None:
        """Run the main application flow."""
        try:
            self.initialize()

            # Get realm input
            realm = self._get_realm_input()

            # Select server
            server = self._select_server()

            # Test authentication
            print("\n正在連線認證伺服器並取得設定資訊，請稍後...")
            print("此過程約需要一分鐘左右。")

            result = self.auth_service.test_authentication(realm, server)

            # Display results
            self._display_results(result)

            # Log results
            self.logging_service.log_result(result)

            # Check if any method succeeded
            if not result.has_any_success:
                print("\n所有認證方法都失敗了。")
                return

            # Generate profile
            profile_config = ProfileConfig(
                realm=result.realm,
                name=str(result.realm),
                short_name=str(result.realm),
                dns=result.dns,
                url=self.config.DEFAULT_URL,
                email=self.config.DEFAULT_EMAIL,
                mschapv2_cert=result.mschapv2_cert.ca_cert_b64
                if result.mschapv2_cert
                else None,
                pap_cert=result.pap_cert.ca_cert_b64 if result.pap_cert else None,
            )

            profile_filename = self.profile_service.generate_profile(profile_config)
            print(f"\n設定檔 {profile_filename} 產生成功！")

        except RateLimitError as e:
            print(f"\n錯誤: {e}")
        except NetworkError as e:
            print(f"\n網路錯誤: {e}")
            print("請檢查網路連線或稍後再試。")
        except EduroamError as e:
            print(f"\n發生錯誤: {e}")
        except KeyboardInterrupt:
            print("\n\n使用者中斷執行。")
        except Exception as e:
            print(f"\n未預期的錯誤: {e}")
            raise

    def _get_realm_input(self) -> Realm:
        """Get realm input from user."""
        while True:
            realm_input = input("請輸入您想要產生設定檔的 realm (例如 mail.edu.tw): ").strip()
            if realm_input:
                realm = Realm(realm_input)
                print(f"您輸入的 realm 是: {realm}")
                return realm

    def _select_server(self) -> TestServer:
        """Select test server from user input."""
        server_id = input(
            "請選擇你想使用的伺服器\n0: 中國科大 (預設)\n1: 西安科大\n選擇: "
        ).strip()

        if not server_id:
            server_id = "0"

        return TestServer.from_id(server_id)

    def _display_results(self, result) -> None:
        """Display authentication results."""
        print("\n" + "=" * 50)
        print("認證測試結果")
        print("=" * 50)

        if result.dns:
            print(f'DNS: "{result.dns}"')
        else:
            print("未找到 DNS 資訊")

        print("\n認證方法測試:")
        if result.mschapv2_success and result.pap_success:
            print("✓ MSCHAP v2 / PAP 憑證已拿取")
        elif result.pap_success:
            print("✓ PAP 憑證已拿取")
            print("✗ MSCHAP v2 憑證未拿取")
        elif result.mschapv2_success:
            print("✓ MSCHAP v2 憑證已拿取")
            print("✗ PAP 憑證未拿取")
        else:
            print("✗ MSCHAP v2 / PAP 憑證未拿取")

        print("=" * 50)


def main() -> None:
    """Application entry point."""
    app = EduroamProfileGenerator()
    app.run()
