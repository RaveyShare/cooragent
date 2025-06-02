# src/sandbox/daytona_client.py

import os
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

try:
    from daytona_sdk import Daytona, DaytonaConfig
except ImportError:
    raise ImportError(
        "daytona-sdk is required. Install it with: pip install daytona-sdk"
    )


@dataclass
class SandboxInfo:
    """Sandbox 信息数据类"""
    id: str
    status: str
    image: str
    created_at: str
    resources: Dict[str, Any]


class DaytonaClient:
    """Daytona SDK 客户端，用于创建和管理 sandbox 环境"""

    def __init__(self, api_key: str = None, api_url: str = None):
        """初始化 Daytona 客户端

        Args:
            api_key: Daytona API 密钥，默认从环境变量获取
            api_url: Daytona API URL，默认从环境变量获取
        """
        self.api_key = api_key or os.environ.get("DAYTONA_API_KEY")
        self.api_url = api_url or os.environ.get("DAYTONA_API_URL")

        # 配置 Daytona
        if self.api_key and self.api_url:
            config = DaytonaConfig(
                api_key=self.api_key,
                api_url=self.api_url
            )
            self.daytona = Daytona(config=config)
        else:
            # 使用默认配置（从环境变量或配置文件读取）
            self.daytona = Daytona()

        self._sandboxes = {}  # 缓存 sandbox 实例

    def create_sandbox(self,
                       image: str = "raveyshare/cooragent:0.0.1",
                       language: str = "python",
                       resources: Dict[str, Any] = None) -> Dict[str, Any]:
        """创建新的 sandbox 环境

        Args:
            image: Docker 镜像名称
            language: 编程语言环境
            resources: 资源限制配置

        Returns:
            包含 sandbox ID 和访问信息的字典
        """
        try:
            # 准备创建参数
            create_params = {
                'image': image,
                'language': language
            }

            # 如果指定了资源限制，添加到参数中
            if resources:
                create_params.update(resources)

            # 创建 sandbox
            sandbox = self.daytona.create(**create_params)

            # 缓存 sandbox 实例
            self._sandboxes[sandbox.id] = sandbox

            return {
                'id': sandbox.id,
                'status': 'running',
                'image': image,
                'language': language,
                'resources': resources or {},
                'created_at': sandbox.created_at if hasattr(sandbox, 'created_at') else None
            }

        except Exception as e:
            raise Exception(f"Failed to create sandbox: {str(e)}")

    def get_sandbox(self, sandbox_id: str) -> Dict[str, Any]:
        """获取 sandbox 信息

        Args:
            sandbox_id: Sandbox ID

        Returns:
            Sandbox 详细信息
        """
        try:
            # 如果在缓存中存在，直接返回
            if sandbox_id in self._sandboxes:
                sandbox = self._sandboxes[sandbox_id]
                return {
                    'id': sandbox.id,
                    'status': getattr(sandbox, 'status', 'running'),
                    'image': getattr(sandbox, 'image', ''),
                    'created_at': getattr(sandbox, 'created_at', None)
                }

            # 尝试重新连接到已存在的 sandbox
            sandbox = self.daytona.get_sandbox(sandbox_id)
            self._sandboxes[sandbox_id] = sandbox

            return {
                'id': sandbox.id,
                'status': getattr(sandbox, 'status', 'running'),
                'image': getattr(sandbox, 'image', ''),
                'created_at': getattr(sandbox, 'created_at', None)
            }

        except Exception as e:
            raise Exception(f"Failed to get sandbox: {str(e)}")

    def list_sandboxes(self) -> List[Dict[str, Any]]:
        """列出所有 sandbox

        Returns:
            Sandbox 列表
        """
        try:
            sandboxes = self.daytona.list_sandboxes()

            result = []
            for sandbox in sandboxes:
                result.append({
                    'id': sandbox.id,
                    'status': getattr(sandbox, 'status', 'running'),
                    'image': getattr(sandbox, 'image', ''),
                    'created_at': getattr(sandbox, 'created_at', None)
                })

            return result

        except Exception as e:
            raise Exception(f"Failed to list sandboxes: {str(e)}")

    def delete_sandbox(self, sandbox_id: str) -> bool:
        """删除 sandbox

        Args:
            sandbox_id: Sandbox ID

        Returns:
            是否成功删除
        """
        try:
            if sandbox_id in self._sandboxes:
                sandbox = self._sandboxes[sandbox_id]
                sandbox.delete()
                del self._sandboxes[sandbox_id]
                return True
            else:
                # 尝试删除不在缓存中的 sandbox
                self.daytona.delete_sandbox(sandbox_id)
                return True

        except Exception as e:
            print(f"Failed to delete sandbox: {str(e)}")
            return False

    def exec_command(self, sandbox_id: str, command: str, workdir: str = None) -> Dict[str, Any]:
        """在 sandbox 中执行命令

        Args:
            sandbox_id: Sandbox ID
            command: 要执行的命令
            workdir: 工作目录（可选）

        Returns:
            命令执行结果
        """
        try:
            # 获取 sandbox 实例
            sandbox = self._get_sandbox_instance(sandbox_id)

            # 执行命令
            if workdir:
                result = sandbox.process.exec(command, workdir=workdir)
            else:
                result = sandbox.process.exec(command)

            return {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'exit_code': result.exit_code,
                'success': result.exit_code == 0
            }

        except Exception as e:
            raise Exception(f"Failed to execute command: {str(e)}")

    def run_code(self, sandbox_id: str, code: str, language: str = "python") -> Dict[str, Any]:
        """在 sandbox 中运行代码

        Args:
            sandbox_id: Sandbox ID
            code: 要运行的代码
            language: 编程语言

        Returns:
            代码执行结果
        """
        try:
            # 获取 sandbox 实例
            sandbox = self._get_sandbox_instance(sandbox_id)

            # 运行代码
            if language.lower() == "python":
                result = sandbox.process.code_run(code)
            else:
                # 对于其他语言，可能需要不同的方法
                result = sandbox.process.code_run(code, language=language)

            return {
                'result': result.result,
                'output': getattr(result, 'output', ''),
                'error': getattr(result, 'error', ''),
                'success': not bool(getattr(result, 'error', ''))
            }

        except Exception as e:
            raise Exception(f"Failed to run code: {str(e)}")

    def upload_file(self, sandbox_id: str, local_path: str, remote_path: str) -> bool:
        """上传文件到 sandbox

        Args:
            sandbox_id: Sandbox ID
            local_path: 本地文件路径
            remote_path: 远程文件路径

        Returns:
            是否成功上传
        """
        try:
            # 获取 sandbox 实例
            sandbox = self._get_sandbox_instance(sandbox_id)

            # 读取本地文件
            with open(local_path, 'rb') as f:
                content = f.read()

            # 上传文件
            sandbox.fs.write(remote_path, content)
            return True

        except Exception as e:
            print(f"Failed to upload file: {str(e)}")
            return False

    def download_file(self, sandbox_id: str, remote_path: str, local_path: str) -> bool:
        """从 sandbox 下载文件

        Args:
            sandbox_id: Sandbox ID
            remote_path: 远程文件路径
            local_path: 本地文件路径

        Returns:
            是否成功下载
        """
        try:
            # 获取 sandbox 实例
            sandbox = self._get_sandbox_instance(sandbox_id)

            # 读取远程文件
            content = sandbox.fs.read(remote_path)

            # 写入本地文件
            with open(local_path, 'wb') as f:
                if isinstance(content, str):
                    f.write(content.encode('utf-8'))
                else:
                    f.write(content)

            return True

        except Exception as e:
            print(f"Failed to download file: {str(e)}")
            return False

    def read_file(self, sandbox_id: str, file_path: str) -> str:
        """读取 sandbox 中的文件内容

        Args:
            sandbox_id: Sandbox ID
            file_path: 文件路径

        Returns:
            文件内容
        """
        try:
            sandbox = self._get_sandbox_instance(sandbox_id)
            content = sandbox.fs.read(file_path)

            if isinstance(content, bytes):
                return content.decode('utf-8')
            return content

        except Exception as e:
            raise Exception(f"Failed to read file: {str(e)}")

    def write_file(self, sandbox_id: str, file_path: str, content: str) -> bool:
        """写入文件到 sandbox

        Args:
            sandbox_id: Sandbox ID
            file_path: 文件路径
            content: 文件内容

        Returns:
            是否成功写入
        """
        try:
            sandbox = self._get_sandbox_instance(sandbox_id)
            sandbox.fs.write(file_path, content)
            return True

        except Exception as e:
            print(f"Failed to write file: {str(e)}")
            return False

    def list_files(self, sandbox_id: str, directory: str = "/") -> List[str]:
        """列出 sandbox 中目录的文件

        Args:
            sandbox_id: Sandbox ID
            directory: 目录路径

        Returns:
            文件列表
        """
        try:
            sandbox = self._get_sandbox_instance(sandbox_id)
            files = sandbox.fs.list(directory)
            return files if isinstance(files, list) else []

        except Exception as e:
            raise Exception(f"Failed to list files: {str(e)}")

    def _get_sandbox_instance(self, sandbox_id: str):
        """获取 sandbox 实例

        Args:
            sandbox_id: Sandbox ID

        Returns:
            Sandbox 实例
        """
        if sandbox_id not in self._sandboxes:
            # 尝试重新连接到已存在的 sandbox
            try:
                sandbox = self.daytona.get_sandbox(sandbox_id)
                self._sandboxes[sandbox_id] = sandbox
            except Exception:
                raise Exception(f"Sandbox {sandbox_id} not found or not accessible")

        return self._sandboxes[sandbox_id]


# 使用示例
if __name__ == "__main__":
    # 创建客户端
    client = DaytonaClient()

    try:
        # 创建 sandbox
        sandbox_info = client.create_sandbox(
            image="python:3.11",
            language="python"
        )
        print(f"Created sandbox: {sandbox_info['id']}")

        # 执行代码
        result = client.run_code(
            sandbox_info['id'],
            'print("Hello from Daytona!")'
        )
        print(f"Code result: {result['result']}")

        # 执行命令
        cmd_result = client.exec_command(
            sandbox_info['id'],
            "ls -la"
        )
        print(f"Command output: {cmd_result['stdout']}")

        # 写入文件
        client.write_file(
            sandbox_info['id'],
            "/tmp/test.py",
            "print('Hello World from file!')"
        )

        # 读取文件
        content = client.read_file(
            sandbox_info['id'],
            "/tmp/test.py"
        )
        print(f"File content: {content}")

        # 列出文件
        files = client.list_files(
            sandbox_info['id'],
            "/tmp"
        )
        print(f"Files in /tmp: {files}")

    except Exception as e:
        print(f"Error: {e}")