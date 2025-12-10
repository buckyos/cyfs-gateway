import os
import shutil
import stat
import sys
import tempfile
import platform
import platform

src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
root_bin_dir = os.path.join(src_dir, "rootfs/bin")
web3_gateway_root_dir = os.path.join(src_dir, "web3-gateway/")
system = platform.system()
ext = ""
if system == "Windows":
    ext = ".exe"
system = platform.system()
ext = ""
if system == "Windows":
    ext = ".exe"

def strip_and_copy_rust_file(rust_target_dir, name, dest, need_dir=False):
    src_file = os.path.join(rust_target_dir, "release", name)
    if need_dir:
        new_name = name.replace("_", "-")
        dest = os.path.join(dest, new_name)
        os.makedirs(dest, exist_ok=True)
    shutil.copy(src_file+ext, dest)

    # no need strip symbol on windows
    if system != "Windows":
        os.system(f"strip {os.path.join(dest, name)}")

def copy_web_apps(src, target):
    dist_dir = os.path.join(src_dir, src, "dist")
    os.makedirs(target, exist_ok=True)
    print(f'copying vite build {dist_dir} to {target}')
    shutil.rmtree(target)
    shutil.copytree(dist_dir, target, copy_function=shutil.copyfile)
    pass

def copy_files(rust_target_dir):
    print("Copying files...")
    # code to copy files
    strip_and_copy_rust_file(rust_target_dir, "cyfs_gateway", root_bin_dir, True)
    web3_gateway_dest_file = os.path.join(web3_gateway_root_dir, "web3_gateway")
    shutil.copyfile(os.path.join(root_bin_dir, "cyfs-gateway","cyfs_gateway"), web3_gateway_dest_file)
    st = os.stat(web3_gateway_dest_file)
    os.chmod(web3_gateway_dest_file, st.st_mode | stat.S_IEXEC)
    strip_and_copy_rust_file(rust_target_dir, "test_server", root_bin_dir, True)
    #copy_web_apps("apps/sys_test", os.path.join(root_bin_dir, "sys_test"))

    print("Files copied successfully!")

if __name__ == "__main__":
    args = sys.argv[1:]
    print("MUST RUN build.py FIRST!!")
    if len(args) == 0:
        print("NEED ARGUMENT: amd64|aarch64")
        exit(1)
    if len(args) > 0:
        temp_dir = tempfile.gettempdir()
        project_name = "buckyos"
        target_dir = os.path.join(temp_dir, "rust_build", project_name)
        if args[0] == "amd64":
            copy_files(os.path.join(target_dir, "x86_64-unknown-linux-musl"))
        elif args[0] == "aarch64":
            copy_files(os.path.join(target_dir, "aarch64-unknown-linux-musl"))
        else:
            print("Invalid argument: clean|amd64|aarch64")
            exit(1)
