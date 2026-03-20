#!/usr/bin/env python3
"""
Container Isolation Module for Picoclaw Security Hardening
Provides Docker-based isolation for tool execution
"""

import docker
import json
import os
import tempfile
import shutil
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

# Default container execution settings
DEFAULT_TIMEOUT = 120  # seconds
DEFAULT_MEMORY_LIMIT = '512m'
DEFAULT_CPU_QUOTA = 50000  # 50% of CPU
ALLOWED_VOLUME_PREFIX = '/workspace'
DEFAULT_WORKSPACE = '/tmp/picoclaw_workspace'


@dataclass
class ExecutionResult:
    """Result of container execution"""
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    container_id: Optional[str] = None


class ContainerIsolationError(Exception):
    """Custom exception for container isolation errors"""
    pass


class ContainerIsolation:
    """
    Docker-based container isolation for secure tool execution.
    
    Features:
    - Non-root user execution by default
    - Timeout handling (configurable, default 120s)
    - Volume mount restrictions (only /workspace allowed)
    - Resource limits (memory, CPU)
    - Network isolation options
    """
    
    def __init__(
        self,
        base_image: str = 'python:3.11-slim',
        timeout: int = DEFAULT_TIMEOUT,
        memory_limit: str = DEFAULT_MEMORY_LIMIT,
        cpu_quota: int = DEFAULT_CPU_QUOTA,
        workspace_dir: str = DEFAULT_WORKSPACE
    ):
        self.base_image = base_image
        self.timeout = timeout
        self.memory_limit = memory_limit
        self.cpu_quota = cpu_quota
        self.workspace_dir = workspace_dir
        
        # Initialize Docker client
        try:
            self.client = docker.from_env()
            self.client.ping()
            logger.info("Docker client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Docker client: {e}")
            self.client = None
        
        # Ensure workspace directory exists
        os.makedirs(self.workspace_dir, exist_ok=True)
    
    def _validate_volume_path(self, host_path: str) -> bool:
        """
        Validate that the host path is allowed for mounting.
        Only paths under ALLOWED_VOLUME_PREFIX are permitted.
        """
        # Normalize paths
        abs_host_path = os.path.abspath(host_path)
        allowed_prefix = os.path.abspath(ALLOWED_VOLUME_PREFIX)
        
        # Check if path is under allowed prefix
        return abs_host_path.startswith(allowed_prefix) or abs_host_path.startswith(self.workspace_dir)
    
    def _prepare_workspace(self, files: Optional[Dict[str, str]] = None) -> str:
        """
        Prepare a workspace directory for execution.
        Creates a unique subdirectory and optionally copies files.
        
        Returns the path to the workspace directory.
        """
        # Create unique workspace
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        workspace = tempfile.mkdtemp(prefix=f'picoclaw_{timestamp}_', dir=self.workspace_dir)
        
        # Set permissions for non-root access
        os.chmod(workspace, 0o755)
        
        # Copy files if provided
        if files:
            for filename, content in files.items():
                filepath = os.path.join(workspace, filename)
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                with open(filepath, 'w') as f:
                    f.write(content)
                os.chmod(filepath, 0o644)
        
        return workspace
    
    def _cleanup_workspace(self, workspace: str):
        """Remove workspace directory after execution"""
        try:
            if os.path.exists(workspace):
                shutil.rmtree(workspace)
                logger.debug(f"Cleaned up workspace: {workspace}")
        except Exception as e:
            logger.warning(f"Failed to cleanup workspace {workspace}: {e}")
    
    def execute(
        self,
        command: str,
        files: Optional[Dict[str, str]] = None,
        env: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        network_disabled: bool = True,
        user: str = 'nobody'
    ) -> ExecutionResult:
        """
        Execute a command in an isolated container.
        
        Args:
            command: The command to execute
            files: Optional dictionary of {filename: content} to create in workspace
            env: Optional environment variables
            timeout: Execution timeout in seconds (default: self.timeout)
            network_disabled: Whether to disable network access (default: True)
            user: User to run as (default: 'nobody' for non-root)
        
        Returns:
            ExecutionResult with stdout, stderr, exit_code, and duration
        """
        if not self.client:
            return ExecutionResult(
                success=False,
                stdout='',
                stderr='Docker client not available',
                exit_code=-1,
                duration_ms=0
            )
        
        start_time = datetime.now()
        timeout = timeout or self.timeout
        workspace = None
        container = None
        
        try:
            # Prepare workspace
            workspace = self._prepare_workspace(files)
            
            # Build volume mounts (only workspace is allowed)
            volumes = {
                workspace: {
                    'bind': '/workspace',
                    'mode': 'rw'
                }
            }
            
            # Build environment
            container_env = env or {}
            container_env['HOME'] = '/workspace'
            container_env['USER'] = user
            
            # Create and run container
            container = self.client.containers.create(
                image=self.base_image,
                command=['/bin/sh', '-c', command],
                volumes=volumes,
                environment=container_env,
                user=user,
                mem_limit=self.memory_limit,
                cpu_quota=self.cpu_quota,
                network_disabled=network_disabled,
                working_dir='/workspace',
                detach=True
            )
            
            container.start()
            logger.info(f"Started container {container.id[:12]} for command execution")
            
            # Wait for completion with timeout
            result = container.wait(timeout=timeout)
            exit_code = result.get('StatusCode', -1)
            
            # Get logs
            stdout = container.logs(stdout=True, stderr=False).decode('utf-8', errors='replace')
            stderr = container.logs(stdout=False, stderr=True).decode('utf-8', errors='replace')
            
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return ExecutionResult(
                success=exit_code == 0,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                duration_ms=duration_ms,
                container_id=container.id[:12]
            )
            
        except docker.errors.APIError as e:
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            logger.error(f"Docker API error: {e}")
            return ExecutionResult(
                success=False,
                stdout='',
                stderr=f"Docker API error: {str(e)}",
                exit_code=-1,
                duration_ms=duration_ms
            )
            
        except Exception as e:
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            logger.error(f"Container execution error: {e}")
            return ExecutionResult(
                success=False,
                stdout='',
                stderr=str(e),
                exit_code=-1,
                duration_ms=duration_ms
            )
            
        finally:
            # Cleanup container
            if container:
                try:
                    container.remove(force=True)
                except Exception as e:
                    logger.warning(f"Failed to remove container: {e}")
            
            # Cleanup workspace
            if workspace:
                self._cleanup_workspace(workspace)
    
    def execute_python(
        self,
        code: str,
        timeout: Optional[int] = None
    ) -> ExecutionResult:
        """
        Execute Python code in an isolated container.
        
        Args:
            code: Python code to execute
            timeout: Execution timeout in seconds
        
        Returns:
            ExecutionResult with execution results
        """
        return self.execute(
            command=f'python3 -c "{code}"',
            timeout=timeout
        )
    
    def execute_script(
        self,
        script_path: str,
        args: Optional[list] = None,
        timeout: Optional[int] = None
    ) -> ExecutionResult:
        """
        Execute a script file in an isolated container.
        
        Args:
            script_path: Path to script file (must be in allowed volume)
            args: Optional list of arguments
            timeout: Execution timeout in seconds
        
        Returns:
            ExecutionResult with execution results
        """
        # Validate script path
        if not self._validate_volume_path(script_path):
            return ExecutionResult(
                success=False,
                stdout='',
                stderr=f'Script path not allowed: {script_path}',
                exit_code=-1,
                duration_ms=0
            )
        
        # Build command
        cmd = script_path
        if args:
            cmd += ' ' + ' '.join(args)
        
        return self.execute(
            command=cmd,
            timeout=timeout,
            network_disabled=False  # Scripts may need network access
        )
    
    def health_check(self) -> Dict[str, Any]:
        """
        Check Docker connectivity and container status.
        
        Returns:
            Dictionary with health status information
        """
        if not self.client:
            return {
                'healthy': False,
                'error': 'Docker client not initialized'
            }
        
        try:
            # Ping Docker daemon
            self.client.ping()
            
            # Get container count
            containers = self.client.containers.list(all=True)
            
            return {
                'healthy': True,
                'docker_version': self.client.version()['Version'],
                'container_count': len(containers),
                'images_available': len(self.client.images.list())
            }
        except Exception as e:
            return {
                'healthy': False,
                'error': str(e)
            }


# Singleton instance
_container_isolation = None

def get_container_isolation() -> ContainerIsolation:
    """Get or create singleton ContainerIsolation instance"""
    global _container_isolation
    if _container_isolation is None:
        _container_isolation = ContainerIsolation()
    return _container_isolation
