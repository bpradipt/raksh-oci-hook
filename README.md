# Introduction
OCI runtime hook for Raksh to be used with Kata containers.
This is a pre-start hook which will do the following before actual execution of the container

- Get secrets inside Kata VM
- Decrypt the encrypted configMap and verify with deployed spec
- Decrypt the user secrets and make it available

# Building

```sh
go build -o bin/hook 
```

# Using it with Kata Containers

1. Ensure `guest_hook_path` is set to `/usr/share/oci/hooks` in kata containers `configuration.toml` file.
   Additionally also set `kernel_params = "agent.debug_console"` which will allow access to the hook logs inside the Kata VM for debugging

2. Copy the `hook` binary to the Kata agent initrd under the following location `${ROOTFS_DIR}/usr/share/oci/hooks/prestart`

    Instructions to build a custom Kata agent is described [here](https://github.com/kata-containers/documentation/blob/master/Developer-Guide.md#create-and-install-rootfs-and-initrd-image)

3. Deploy container. 
    ```sh
    kubectl apply -f examples/sample.yaml
    ```

4. Exec a shell inside the container and check the mount points

    ```sh
    kubectl exec -it nginx

    root@nginx:~# mount
    ```

5. Access the hook logs

    Get the console.sock file path for the Kata VM. It's part of the Qemu argument

    ```sh
    ps aux | grep qemu
    ```
    Look for the console.sock entry which will be of the following format: `/run/vc/vm/<UUID>/console.sock`

    Connect to the console
    ```sh
    socat stdin,raw,echo=0,escape=0x11 unix-connect:"<path_to_console.sock>"
    ```

    Log files are under `/tmp`


