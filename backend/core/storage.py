"""
Storage backend abstraction
Supports local filesystem and S3-compatible storage
"""

import os
import shutil
import boto3
import logging
from abc import ABC, abstractmethod
from typing import Optional, BinaryIO
from pathlib import Path

logger = logging.getLogger(__name__)


class StorageBackend(ABC):
    """Abstract storage interface"""

    @abstractmethod
    async def upload(self, key: str, data: BinaryIO) -> str:
        """Upload data, return storage URL"""
        pass

    @abstractmethod
    async def download(self, key: str) -> bytes:
        """Download data"""
        pass

    @abstractmethod
    async def delete(self, key: str):
        """Delete object"""
        pass

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if object exists"""
        pass

    @abstractmethod
    async def get_size(self, key: str) -> int:
        """Get object size in bytes"""
        pass


class LocalStorageBackend(StorageBackend):
    """
    Local filesystem storage
    Default for OSS and simple deployments
    """

    def __init__(self, base_path: str = "/var/lib/vnbui/backups"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)

    async def upload(self, key: str, data: BinaryIO) -> str:
        """Save to local filesystem"""
        file_path = self.base_path / key

        # Create parent directories
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # Write data
        with open(file_path, "wb") as f:
            f.write(data.read())

        logger.info(f"Uploaded to local storage: {key}")
        return f"file://{file_path}"

    async def download(self, key: str) -> bytes:
        """Read from local filesystem"""
        file_path = self.base_path / key

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {key}")

        with open(file_path, "rb") as f:
            return f.read()

    async def delete(self, key: str):
        """Delete file or directory from local filesystem"""
        file_path = self.base_path / key

        if file_path.is_dir():
            shutil.rmtree(file_path)
            logger.info(f"Deleted directory from local storage: {key}")
        elif file_path.exists():
            file_path.unlink()
            logger.info(f"Deleted from local storage: {key}")

    async def exists(self, key: str) -> bool:
        """Check if file exists"""
        file_path = self.base_path / key
        return file_path.exists()

    async def get_size(self, key: str) -> int:
        """Get file size"""
        file_path = self.base_path / key

        if not file_path.exists():
            return 0

        return file_path.stat().st_size


class S3StorageBackend(StorageBackend):
    """
    S3-compatible storage (AWS S3, MinIO, etc.)
    Available in all editions for cloud backups
    """

    def __init__(
        self,
        bucket: str,
        endpoint_url: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        region: str = "us-east-1",
    ):
        self.bucket = bucket
        self.endpoint_url = endpoint_url
        self.region = region

        # Initialize S3 client
        self.s3 = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
        )

        # Verify bucket exists
        try:
            self.s3.head_bucket(Bucket=bucket)
        except Exception as e:
            logger.warning(f"S3 bucket {bucket} check failed: {e}")

    async def upload(self, key: str, data: BinaryIO) -> str:
        """Upload to S3"""
        try:
            self.s3.upload_fileobj(data, self.bucket, key)
            logger.info(f"Uploaded to S3: s3://{self.bucket}/{key}")
            return f"s3://{self.bucket}/{key}"
        except Exception as e:
            logger.error(f"S3 upload failed: {e}")
            raise

    async def download(self, key: str) -> bytes:
        """Download from S3"""
        try:
            response = self.s3.get_object(Bucket=self.bucket, Key=key)
            return response["Body"].read()
        except Exception as e:
            logger.error(f"S3 download failed: {e}")
            raise

    async def delete(self, key: str):
        """Delete all objects under key prefix from S3.

        Backup data is stored as multiple objects under a prefix
        (e.g. prefix/backup-id/file1, prefix/backup-id/file2).
        Lists and batch-deletes all objects matching the prefix.
        """
        try:
            deleted = 0
            paginator = self.s3.get_paginator("list_objects_v2")
            # Ensure prefix ends with / to avoid matching partial names
            prefix = key.rstrip("/") + "/"
            for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
                objects = page.get("Contents", [])
                if not objects:
                    continue
                self.s3.delete_objects(
                    Bucket=self.bucket,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objects]},
                )
                deleted += len(objects)

            if deleted:
                logger.info(f"Deleted {deleted} objects from S3: {prefix}")
            else:
                # Fall back to single-object delete (exact key match)
                self.s3.delete_object(Bucket=self.bucket, Key=key)
                logger.info(f"Deleted from S3: {key}")
        except Exception as e:
            logger.error(f"S3 delete failed for {key}: {e}")
            raise

    async def exists(self, key: str) -> bool:
        """Check if object exists in S3"""
        try:
            self.s3.head_object(Bucket=self.bucket, Key=key)
            return True
        except Exception:
            return False

    async def get_size(self, key: str) -> int:
        """Get object size from S3"""
        try:
            response = self.s3.head_object(Bucket=self.bucket, Key=key)
            return response["ContentLength"]
        except Exception:
            return 0


class TieredStorageBackend(StorageBackend):
    """
    Multi-tier storage with hot/cold tiers
    Commercial feature for cost optimization
    """

    def __init__(
        self,
        hot_backend: StorageBackend,
        cold_backend: StorageBackend,
        tier_after_days: int = 30,
    ):
        self.hot = hot_backend
        self.cold = cold_backend
        self.tier_after_days = tier_after_days

    async def upload(self, key: str, data: BinaryIO) -> str:
        """Upload to hot tier"""
        # Always upload to hot tier first
        url = await self.hot.upload(key, data)

        # TODO: Schedule tiering job
        # schedule_tiering(key, self.tier_after_days)

        return url

    async def download(self, key: str) -> bytes:
        """Download from appropriate tier"""
        # Check hot tier first
        if await self.hot.exists(key):
            return await self.hot.download(key)

        # Fall back to cold tier
        return await self.cold.download(key)

    async def delete(self, key: str):
        """Delete from all tiers"""
        # Delete from both tiers
        if await self.hot.exists(key):
            await self.hot.delete(key)

        if await self.cold.exists(key):
            await self.cold.delete(key)

    async def exists(self, key: str) -> bool:
        """Check both tiers"""
        return await self.hot.exists(key) or await self.cold.exists(key)

    async def get_size(self, key: str) -> int:
        """Get size from appropriate tier"""
        if await self.hot.exists(key):
            return await self.hot.get_size(key)

        return await self.cold.get_size(key)


def get_storage_backend() -> StorageBackend:
    """
    Factory to get appropriate storage backend based on configuration

    Returns:
        StorageBackend instance based on environment config
    """
    storage_type = os.getenv("STORAGE_TYPE", "local")

    if storage_type == "local":
        base_path = os.getenv("STORAGE_PATH", "/var/lib/vnbui/backups")
        return LocalStorageBackend(base_path)

    elif storage_type == "s3":
        return S3StorageBackend(
            bucket=os.getenv("S3_BUCKET"),
            endpoint_url=os.getenv("S3_ENDPOINT"),
            access_key=os.getenv("S3_ACCESS_KEY"),
            secret_key=os.getenv("S3_SECRET_KEY"),
            region=os.getenv("S3_REGION", "us-east-1"),
        )

    elif storage_type == "tiered":
        # Hot tier: local or S3
        # Cold tier: S3 with different storage class
        hot = LocalStorageBackend()
        cold = S3StorageBackend(
            bucket=os.getenv("S3_COLD_BUCKET"),
            endpoint_url=os.getenv("S3_ENDPOINT"),
            access_key=os.getenv("S3_ACCESS_KEY"),
            secret_key=os.getenv("S3_SECRET_KEY"),
            region=os.getenv("S3_REGION", "us-east-1"),
        )
        return TieredStorageBackend(hot, cold)

    else:
        logger.warning(f"Unknown storage type {storage_type}, using local")
        return LocalStorageBackend()


# Global storage instance
storage = get_storage_backend()
