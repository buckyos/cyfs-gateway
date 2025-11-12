import argparse
import os
import sys
import platform
import subprocess
if __name__ == "__main__":
    config_file = "cyfs_gateway.json"
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
    rootfs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rootfs")
    config_path = os.path.join(rootfs_dir, "etc", config_file)
    # 进入rootfs目录，并执行cyfs-gateway --config config的绝对路径
    print(f'run cyfs_gateway --config_file {config_path}')
    subprocess.run(["bin/cyfs_gateway/cyfs_gateway", "--config_file", config_path], cwd=rootfs_dir)