# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/test_translate_grpc.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: MCP Gateway Contributors

Tests for gRPC to MCP translation module.
"""

# Standard
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio

# Third-Party
import pytest

# Check if gRPC is available
try:
    import grpc  # noqa: F401

    GRPC_AVAILABLE = True
except ImportError:
    GRPC_AVAILABLE = False

# Skip all tests in this module if gRPC is not available
pytestmark = pytest.mark.skipif(not GRPC_AVAILABLE, reason="gRPC packages not installed")

# First-Party
from mcpgateway.translate_grpc import (
    GrpcEndpoint,
    GrpcToMcpTranslator,
    expose_grpc_via_sse,
)


class TestGrpcEndpoint:
    """Test suite for GrpcEndpoint."""

    @pytest.fixture
    def endpoint(self):
        """Create a basic gRPC endpoint."""
        return GrpcEndpoint(
            target="localhost:50051",
            reflection_enabled=True,
            tls_enabled=False,
        )

    @pytest.fixture
    def endpoint_with_tls(self):
        """Create a gRPC endpoint with TLS."""
        return GrpcEndpoint(
            target="secure.example.com:443",
            reflection_enabled=True,
            tls_enabled=True,
            tls_cert_path="/path/to/cert.pem",
            tls_key_path="/path/to/key.pem",
        )

    @pytest.fixture
    def endpoint_with_metadata(self):
        """Create a gRPC endpoint with metadata."""
        return GrpcEndpoint(
            target="api.example.com:50051",
            reflection_enabled=True,
            metadata={"authorization": "Bearer test-token", "x-tenant-id": "customer-1"},
        )

    def test_endpoint_initialization(self, endpoint):
        """Test basic endpoint initialization."""
        assert endpoint._target == "localhost:50051"
        assert endpoint._reflection_enabled is True
        assert endpoint._tls_enabled is False
        assert endpoint._channel is None
        assert len(endpoint._services) == 0

    def test_endpoint_with_tls_initialization(self, endpoint_with_tls):
        """Test endpoint with TLS configuration."""
        assert endpoint_with_tls._tls_enabled is True
        assert endpoint_with_tls._tls_cert_path == "/path/to/cert.pem"
        assert endpoint_with_tls._tls_key_path == "/path/to/key.pem"

    def test_endpoint_with_metadata_initialization(self, endpoint_with_metadata):
        """Test endpoint with metadata headers."""
        assert endpoint_with_metadata._metadata == {
            "authorization": "Bearer test-token",
            "x-tenant-id": "customer-1",
        }

    @patch("mcpgateway.translate_grpc.grpc")
    async def test_start_insecure_channel(self, mock_grpc, endpoint):
        """Test starting endpoint with insecure channel."""
        mock_channel = MagicMock()
        mock_grpc.insecure_channel.return_value = mock_channel

        with patch.object(endpoint, "_discover_services", new_callable=AsyncMock):
            await endpoint.start()

        mock_grpc.insecure_channel.assert_called_once_with("localhost:50051")
        assert endpoint._channel == mock_channel

    @patch("mcpgateway.translate_grpc.grpc")
    @patch("builtins.open", create=True)
    async def test_start_secure_channel_with_certs(self, mock_open, mock_grpc, endpoint_with_tls):
        """Test starting endpoint with TLS certificates."""
        mock_channel = MagicMock()
        mock_grpc.secure_channel.return_value = mock_channel
        mock_grpc.ssl_channel_credentials.return_value = MagicMock()

        # Mock file reads for cert and key
        mock_file = MagicMock()
        mock_file.read.return_value = b"cert_data"
        mock_open.return_value.__enter__.return_value = mock_file

        with patch.object(endpoint_with_tls, "_discover_services", new_callable=AsyncMock):
            await endpoint_with_tls.start()

        assert endpoint_with_tls._channel == mock_channel
        mock_grpc.secure_channel.assert_called_once()

    @patch("mcpgateway.translate_grpc.grpc")
    async def test_start_secure_channel_without_certs(self, mock_grpc):
        """Test starting endpoint with TLS but no cert files."""
        endpoint = GrpcEndpoint(
            target="secure.example.com:443",
            reflection_enabled=True,
            tls_enabled=True,
        )

        mock_channel = MagicMock()
        mock_grpc.secure_channel.return_value = mock_channel
        mock_grpc.ssl_channel_credentials.return_value = MagicMock()

        with patch.object(endpoint, "_discover_services", new_callable=AsyncMock):
            await endpoint.start()

        mock_grpc.ssl_channel_credentials.assert_called_once_with()
        assert endpoint._channel == mock_channel

    @patch("mcpgateway.translate_grpc.grpc")
    @patch("mcpgateway.translate_grpc.reflection_pb2_grpc")
    @patch("mcpgateway.translate_grpc.reflection_pb2")
    async def test_discover_services_success(
        self, mock_reflection_pb2, mock_reflection_grpc, mock_grpc, endpoint
    ):
        """Test successful service discovery."""
        # Setup mocks
        mock_channel = MagicMock()
        endpoint._channel = mock_channel

        mock_stub = MagicMock()
        mock_reflection_grpc.ServerReflectionStub.return_value = mock_stub

        # Mock service discovery response
        mock_service = MagicMock()
        mock_service.name = "test.TestService"

        mock_list_response = MagicMock()
        mock_list_response.service = [mock_service]

        mock_response = MagicMock()
        mock_response.HasField.return_value = True
        mock_response.list_services_response = mock_list_response

        mock_stub.ServerReflectionInfo.return_value = [mock_response]

        # Mock _discover_service_details to populate services
        with patch.object(endpoint, "_discover_service_details", new_callable=AsyncMock) as mock_details:
            async def populate_service(stub, service_name):
                endpoint._services[service_name] = {
                    "name": service_name,
                    "methods": [],
                }
            mock_details.side_effect = populate_service

            await endpoint._discover_services()

        assert "test.TestService" in endpoint._services
        assert endpoint._services["test.TestService"]["name"] == "test.TestService"

    @patch("mcpgateway.translate_grpc.grpc")
    @patch("mcpgateway.translate_grpc.reflection_pb2_grpc")
    async def test_discover_services_skip_reflection_service(
        self, mock_reflection_grpc, mock_grpc, endpoint
    ):
        """Test that ServerReflection service is skipped."""
        mock_channel = MagicMock()
        endpoint._channel = mock_channel

        mock_stub = MagicMock()
        mock_reflection_grpc.ServerReflectionStub.return_value = mock_stub

        # Mock response with ServerReflection service (should be skipped)
        mock_service1 = MagicMock()
        mock_service1.name = "grpc.reflection.v1alpha.ServerReflection"

        mock_service2 = MagicMock()
        mock_service2.name = "test.TestService"

        mock_list_response = MagicMock()
        mock_list_response.service = [mock_service1, mock_service2]

        mock_response = MagicMock()
        mock_response.HasField.return_value = True
        mock_response.list_services_response = mock_list_response

        mock_stub.ServerReflectionInfo.return_value = [mock_response]

        # Mock _discover_service_details to populate only non-reflection services
        with patch.object(endpoint, "_discover_service_details", new_callable=AsyncMock) as mock_details:
            async def populate_service(stub, service_name):
                endpoint._services[service_name] = {
                    "name": service_name,
                    "methods": [],
                }
            mock_details.side_effect = populate_service

            await endpoint._discover_services()

        # ServerReflection should be skipped
        assert "grpc.reflection.v1alpha.ServerReflection" not in endpoint._services
        # TestService should be included
        assert "test.TestService" in endpoint._services

    @patch("mcpgateway.translate_grpc.grpc")
    @patch("mcpgateway.translate_grpc.reflection_pb2_grpc")
    async def test_discover_services_error(self, mock_reflection_grpc, mock_grpc, endpoint):
        """Test service discovery error handling."""
        mock_channel = MagicMock()
        endpoint._channel = mock_channel

        mock_stub = MagicMock()
        mock_reflection_grpc.ServerReflectionStub.return_value = mock_stub
        mock_stub.ServerReflectionInfo.side_effect = Exception("Connection failed")

        with pytest.raises(Exception) as exc_info:
            await endpoint._discover_services()

        assert "Connection failed" in str(exc_info.value)

    async def test_invoke_service_not_found(self, endpoint):
        """Test invoke with non-existent service."""
        with pytest.raises(ValueError, match="Service .* not found"):
            await endpoint.invoke(
                service="test.TestService",
                method="TestMethod",
                request_data={"param": "value"},
            )

    async def test_invoke_streaming_service_not_found(self, endpoint):
        """Test invoke_streaming with non-existent service."""
        with pytest.raises(ValueError, match="Service .* not found"):
            async for _ in endpoint.invoke_streaming(
                service="test.TestService",
                method="StreamMethod",
                request_data={"param": "value"},
            ):
                pass

    async def test_close(self, endpoint):
        """Test closing the gRPC channel."""
        mock_channel = MagicMock()
        endpoint._channel = mock_channel

        await endpoint.close()

        mock_channel.close.assert_called_once()

    async def test_close_no_channel(self, endpoint):
        """Test closing when no channel exists."""
        # Should not raise an error
        await endpoint.close()

    def test_get_services(self, endpoint):
        """Test getting list of discovered services."""
        endpoint._services = {
            "service1": {"name": "service1"},
            "service2": {"name": "service2"},
        }

        services = endpoint.get_services()

        assert len(services) == 2
        assert "service1" in services
        assert "service2" in services

    def test_get_methods(self, endpoint):
        """Test getting methods for a service."""
        endpoint._services = {
            "test.TestService": {
                "name": "test.TestService",
                "methods": [{"name": "Method1"}, {"name": "Method2"}],
            }
        }

        methods = endpoint.get_methods("test.TestService")

        assert len(methods) == 2
        assert "Method1" in methods
        assert "Method2" in methods

    def test_get_methods_nonexistent_service(self, endpoint):
        """Test getting methods for non-existent service."""
        methods = endpoint.get_methods("nonexistent.Service")

        assert len(methods) == 0


class TestGrpcToMcpTranslator:
    """Test suite for GrpcToMcpTranslator."""

    @pytest.fixture
    def endpoint(self):
        """Create a mock gRPC endpoint."""
        endpoint = MagicMock(spec=GrpcEndpoint)
        endpoint.get_methods.return_value = ["Method1", "Method2"]
        endpoint._services = {
            "test.TestService": {
                "name": "test.TestService",
                "methods": [
                    {"name": "Method1", "input_type": ".test.Request1", "output_type": ".test.Response1"},
                    {"name": "Method2", "input_type": ".test.Request2", "output_type": ".test.Response2"},
                ]
            }
        }
        endpoint._pool = MagicMock()
        endpoint._pool.FindMessageTypeByName.side_effect = KeyError("Not found")
        return endpoint

    @pytest.fixture
    def translator(self, endpoint):
        """Create a translator instance."""
        return GrpcToMcpTranslator(endpoint)

    def test_translator_initialization(self, translator, endpoint):
        """Test translator initialization."""
        assert translator._endpoint == endpoint

    def test_grpc_service_to_mcp_server(self, translator, endpoint):
        """Test converting gRPC service to MCP server definition."""
        result = translator.grpc_service_to_mcp_server("test.TestService")

        assert result["name"] == "test.TestService"
        assert result["description"] == "gRPC service: test.TestService"
        assert "sse" in result["transport"]
        assert "http" in result["transport"]
        assert "tools" in result

    def test_grpc_methods_to_mcp_tools(self, translator, endpoint):
        """Test converting gRPC methods to MCP tools."""
        result = translator.grpc_methods_to_mcp_tools("test.TestService")

        assert len(result) == 2
        assert result[0]["name"] == "test.TestService.Method1"
        assert result[0]["description"] == "gRPC method test.TestService.Method1"
        assert "inputSchema" in result[0]

    def test_protobuf_to_json_schema(self, translator):
        """Test converting protobuf descriptor to JSON schema."""
        mock_descriptor = MagicMock()
        mock_descriptor.fields = []  # Empty message

        result = translator.protobuf_to_json_schema(mock_descriptor)

        assert result["type"] == "object"
        assert "properties" in result
        assert "required" in result


class TestExposeGrpcViaSse:
    """Test suite for expose_grpc_via_sse utility function."""

    @patch("mcpgateway.translate_grpc.GrpcEndpoint")
    @patch("mcpgateway.translate_grpc.asyncio.sleep")
    async def test_expose_grpc_via_sse_basic(self, mock_sleep, mock_endpoint_class):
        """Test basic gRPC exposure via SSE."""
        # Mock the endpoint
        mock_endpoint = MagicMock()
        mock_endpoint.start = AsyncMock()
        mock_endpoint.close = AsyncMock()
        mock_endpoint.get_services.return_value = ["test.TestService"]
        mock_endpoint_class.return_value = mock_endpoint

        # Mock sleep to raise KeyboardInterrupt after first call
        mock_sleep.side_effect = KeyboardInterrupt()

        try:
            await expose_grpc_via_sse(target="localhost:50051", port=9000)
        except KeyboardInterrupt:
            pass

        mock_endpoint.start.assert_called_once()
        mock_endpoint.close.assert_called_once()

    @patch("mcpgateway.translate_grpc.GrpcEndpoint")
    @patch("mcpgateway.translate_grpc.asyncio.sleep")
    async def test_expose_grpc_via_sse_with_tls(self, mock_sleep, mock_endpoint_class):
        """Test gRPC exposure with TLS configuration."""
        mock_endpoint = MagicMock()
        mock_endpoint.start = AsyncMock()
        mock_endpoint.close = AsyncMock()
        mock_endpoint.get_services.return_value = []
        mock_endpoint_class.return_value = mock_endpoint

        mock_sleep.side_effect = KeyboardInterrupt()

        try:
            await expose_grpc_via_sse(
                target="secure.example.com:443",
                port=9000,
                tls_enabled=True,
                tls_cert="/path/to/cert.pem",
                tls_key="/path/to/key.pem",
            )
        except KeyboardInterrupt:
            pass

        # Verify endpoint was created with TLS config
        mock_endpoint_class.assert_called_once_with(
            target="secure.example.com:443",
            reflection_enabled=True,
            tls_enabled=True,
            tls_cert_path="/path/to/cert.pem",
            tls_key_path="/path/to/key.pem",
            metadata=None,
        )

    @patch("mcpgateway.translate_grpc.GrpcEndpoint")
    @patch("mcpgateway.translate_grpc.asyncio.sleep")
    async def test_expose_grpc_via_sse_with_metadata(self, mock_sleep, mock_endpoint_class):
        """Test gRPC exposure with metadata headers."""
        mock_endpoint = MagicMock()
        mock_endpoint.start = AsyncMock()
        mock_endpoint.close = AsyncMock()
        mock_endpoint.get_services.return_value = []
        mock_endpoint_class.return_value = mock_endpoint

        mock_sleep.side_effect = KeyboardInterrupt()

        metadata = {"authorization": "Bearer token", "x-tenant": "test"}

        try:
            await expose_grpc_via_sse(
                target="api.example.com:50051",
                port=9000,
                metadata=metadata,
            )
        except KeyboardInterrupt:
            pass

        # Verify metadata was passed
        call_args = mock_endpoint_class.call_args
        assert call_args[1]["metadata"] == metadata
