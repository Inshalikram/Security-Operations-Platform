from minio import Minio
from minio.error import S3Error
import os
import io


minio_client = Minio(
    os.getenv("MINIO_ENDPOINT", "minio:9000"),
    access_key=os.getenv("MINIO_ROOT_USER", "sop_admin"),
    secret_key=os.getenv("MINIO_ROOT_PASSWORD", "changeme123"),
    secure=False,
)


def ensure_bucket(bucket: str):
    try:
        if not minio_client.bucket_exists(bucket):
            minio_client.make_bucket(bucket)
    except S3Error as e:
        print("MINIO BUCKET ERROR:", e)


def upload_bytes(bucket: str, filename: str, content: bytes, content_type: str = "application/octet-stream"):
    """Uploads raw bytes, returns the object path or None on failure."""
    try:
        ensure_bucket(bucket)
        minio_client.put_object(
            bucket,
            filename,
            io.BytesIO(content),
            length=len(content),
            content_type=content_type,
        )
        return f"{bucket}/{filename}"
    except S3Error as e:
        print("MINIO UPLOAD ERROR:", e)
        return None


def get_presigned_url(bucket: str, filename: str, expires_seconds: int = 3600):
    """Returns a temporary download URL for a stored object."""
    try:
        from datetime import timedelta
        return minio_client.presigned_get_object(
            bucket, filename, expires=timedelta(seconds=expires_seconds)
        )
    except S3Error as e:
        print("MINIO PRESIGN ERROR:", e)
        return None