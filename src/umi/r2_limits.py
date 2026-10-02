"""Conservative Cloudflare R2 S3 multipart limits shared by signed protocols."""

R2_MINIMUM_PART_BYTES = 5 * 1024**2
R2_MAXIMUM_PART_BYTES = 5 * 1024**3 - 5 * 1024**2
R2_MAXIMUM_PARTS = 10_000
R2_MAXIMUM_MULTIPART_BYTES = 5 * 1024**4 - 5 * 1024**3
