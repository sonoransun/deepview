"""Tests for extended configuration subsystems (storage / containers / offload / remote)."""
from __future__ import annotations

from pathlib import Path

from deepview.core.config import (
    ContainersConfig,
    DeepViewConfig,
    OffloadConfig,
    RemoteEndpointConfig,
    StorageConfig,
)


class TestStorageConfigDefaults:
    def test_defaults_present(self) -> None:
        config = DeepViewConfig()
        assert isinstance(config.storage, StorageConfig)
        assert config.storage.default_page_size == 4096
        assert config.storage.default_spare_size == 64
        assert config.storage.default_ecc == "bch8"
        assert config.storage.default_ftl == "badblock"
        assert config.storage.default_spare_layout == "onfi"
        assert config.storage.prefer_native_filesystems is True

    def test_override_storage_sticks(self) -> None:
        config = DeepViewConfig(storage=StorageConfig(default_page_size=2048))
        assert config.storage.default_page_size == 2048
        # Other fields retain their defaults.
        assert config.storage.default_spare_size == 64
        assert config.storage.default_ecc == "bch8"


class TestContainersConfigDefaults:
    def test_defaults_present(self) -> None:
        config = DeepViewConfig()
        assert isinstance(config.containers, ContainersConfig)
        assert config.containers.allow_write is False
        assert config.containers.cache_sectors == 256
        assert config.containers.passphrase_attempts == 100
        assert config.containers.try_hidden is False
        assert config.containers.pbkdf2_default_iterations == 1000
        assert config.containers.argon2_default_memory_kib == 65536
        assert config.containers.argon2_default_iterations == 3
        assert config.containers.argon2_default_parallelism == 4

    def test_override_containers(self) -> None:
        config = DeepViewConfig(
            containers=ContainersConfig(allow_write=True, passphrase_attempts=10)
        )
        assert config.containers.allow_write is True
        assert config.containers.passphrase_attempts == 10
        # Unchanged defaults.
        assert config.containers.cache_sectors == 256


class TestOffloadConfigDefaults:
    def test_defaults_present(self) -> None:
        config = DeepViewConfig()
        assert isinstance(config.offload, OffloadConfig)
        assert config.offload.default_backend == "process"
        assert config.offload.process_workers is None
        assert config.offload.thread_workers is None
        assert config.offload.gpu_enabled is False

    def test_override_offload(self) -> None:
        config = DeepViewConfig(
            offload=OffloadConfig(
                default_backend="gpu-cuda", process_workers=8, gpu_enabled=True
            )
        )
        assert config.offload.default_backend == "gpu-cuda"
        assert config.offload.process_workers == 8
        assert config.offload.gpu_enabled is True


class TestRemoteEndpointConfig:
    def test_default_list_is_empty(self) -> None:
        config = DeepViewConfig()
        assert config.remote_endpoints == []

    def test_remote_endpoint_list_preserved(self) -> None:
        endpoint = RemoteEndpointConfig(
            host="10.0.0.7", transport="ssh", username="user"
        )
        config = DeepViewConfig(remote_endpoints=[endpoint])
        assert len(config.remote_endpoints) == 1
        stored = config.remote_endpoints[0]
        assert stored.host == "10.0.0.7"
        assert stored.transport == "ssh"
        assert stored.username == "user"
        # Defaults on an unspecified field.
        assert stored.require_tls is True
        assert stored.port is None
        assert stored.extra == {}

    def test_remote_endpoint_full_fields(self) -> None:
        endpoint = RemoteEndpointConfig(
            host="target.example",
            transport="grpc",
            port=50051,
            username="agent",
            identity_file=Path("/tmp/id_ed25519"),
            password_env="DV_PASS",
            known_hosts=Path("/tmp/known_hosts"),
            tls_ca=Path("/tmp/ca.pem"),
            require_tls=False,
            extra={"role": "primary"},
        )
        assert endpoint.port == 50051
        assert endpoint.identity_file == Path("/tmp/id_ed25519")
        assert endpoint.tls_ca == Path("/tmp/ca.pem")
        assert endpoint.require_tls is False
        assert endpoint.extra == {"role": "primary"}

    def test_multiple_endpoints_preserved(self) -> None:
        endpoints = [
            RemoteEndpointConfig(host="a", transport="ssh"),
            RemoteEndpointConfig(host="b", transport="tcp", port=9000),
            RemoteEndpointConfig(host="c", transport="dma"),
        ]
        config = DeepViewConfig(remote_endpoints=endpoints)
        assert [e.host for e in config.remote_endpoints] == ["a", "b", "c"]
        assert config.remote_endpoints[1].port == 9000


class TestConfigTomlRoundTrip:
    def test_load_toml_with_new_sections(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
log_level = "debug"

[storage]
default_page_size = 8192
default_ecc = "hamming"
prefer_native_filesystems = false

[containers]
allow_write = true
passphrase_attempts = 5
argon2_default_memory_kib = 131072

[offload]
default_backend = "thread"
thread_workers = 16
gpu_enabled = true

[[remote_endpoints]]
host = "10.0.0.7"
transport = "ssh"
username = "user"
port = 2222

[[remote_endpoints]]
host = "fw.example"
transport = "dma"
require_tls = false
"""
        )
        config = DeepViewConfig.load(config_file)

        assert config.log_level == "debug"

        assert config.storage.default_page_size == 8192
        assert config.storage.default_ecc == "hamming"
        assert config.storage.prefer_native_filesystems is False
        # Untouched field still at default.
        assert config.storage.default_ftl == "badblock"

        assert config.containers.allow_write is True
        assert config.containers.passphrase_attempts == 5
        assert config.containers.argon2_default_memory_kib == 131072
        assert config.containers.argon2_default_iterations == 3

        assert config.offload.default_backend == "thread"
        assert config.offload.thread_workers == 16
        assert config.offload.gpu_enabled is True
        assert config.offload.process_workers is None

        assert len(config.remote_endpoints) == 2
        first, second = config.remote_endpoints
        assert first.host == "10.0.0.7"
        assert first.transport == "ssh"
        assert first.username == "user"
        assert first.port == 2222
        assert first.require_tls is True  # default preserved
        assert second.host == "fw.example"
        assert second.transport == "dma"
        assert second.require_tls is False
